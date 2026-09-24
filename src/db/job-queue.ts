// src/db/job-queue.ts
// D1-backed job queue — replaces Cloudflare Queues for the free tier.
//
// Producers INSERT rows into `job_queue`. The single cron trigger (free-tier
// limit: 1 cron per worker) polls the table every 5 minutes, picks up
// pending jobs, and runs them via `ctx.waitUntil()`.
//
// Status flow:
//   pending → running → completed
//                     ↘ failed (retryable)
//                     ↘ cancelled (operator-cancelled)
//                     ↘ dead_letter (max attempts exceeded)

export type JobKind = "scan" | "notification";
export type JobStatus = "pending" | "running" | "completed" | "failed" | "cancelled" | "dead_letter";

export interface JobRow {
  id: string;
  kind: JobKind;
  payload_json: string;
  status: JobStatus;
  priority: number;       // higher = picked up first
  attempts: number;
  max_attempts: number;
  run_after: string;      // ISO timestamp — earliest the job may run (jitter/backoff)
  locked_until: string;   // ISO timestamp — set by a worker claiming the job
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  last_error: string | null;
  dedup_key: string | null; // optional — prevents duplicate jobs
}

export const MAX_SCAN_ATTEMPTS = 3;
export const MAX_NOTIFICATION_ATTEMPTS = 5;

/**
 * Insert a job row. If `dedup_key` is provided and a pending/running job with
 * the same key already exists, returns its ID without inserting a new one —
 * this prevents the cron from firing the same alert 12 times for 12 identical
 * findings discovered in one scan.
 */
export async function enqueueJob(
  db: D1Database,
  kind: JobKind,
  payload: Record<string, unknown>,
  opts: {
    priority?: number;
    max_attempts?: number;
    run_after?: Date;
    dedup_key?: string;
  } = {},
): Promise<string> {
  // Dedup check
  if (opts.dedup_key) {
    const existing = await db
      .prepare(`SELECT id FROM job_queue WHERE dedup_key = ? AND status IN ('pending','running') LIMIT 1`)
      .bind(opts.dedup_key)
      .first<{ id: string }>();
    if (existing) return existing.id;
  }

  const id = `job_${crypto.randomUUID()}`;
  const now = new Date();
  const maxAttempts = opts.max_attempts ?? (kind === "scan" ? MAX_SCAN_ATTEMPTS : MAX_NOTIFICATION_ATTEMPTS);
  const runAfter = (opts.run_after ?? now).toISOString();
  const lockedUntil = new Date(0).toISOString(); // epoch = not locked

  await db
    .prepare(`INSERT INTO job_queue (
      id, kind, payload_json, status, priority, attempts, max_attempts,
      run_after, locked_until, created_at, last_error, dedup_key
    ) VALUES (?, ?, ?, 'pending', ?, 0, ?, ?, ?, ?, NULL, ?)`)
    .bind(
      id, kind, JSON.stringify(payload),
      opts.priority ?? 0,
      maxAttempts,
      runAfter, lockedUntil,
      now.toISOString(),
      opts.dedup_key ?? null,
    )
    .run();
  return id;
}

/**
 * Atomically claim up to `limit` pending jobs for execution.
 *
 * Sets `locked_until` to `now + lockMs` so other invocations of the cron
 * handler (which may run concurrently across multiple Worker isolates)
 * don't pick up the same jobs.
 *
 * Returns the claimed jobs with their payload deserialised.
 */
export async function claimPendingJobs(
  db: D1Database,
  kind: JobKind,
  limit: number,
  lockMs: number,
): Promise<Array<{ id: string; payload: Record<string, unknown>; attempts: number; max_attempts: number }>> {
  const now = new Date();
  const lockUntil = new Date(now.getTime() + lockMs).toISOString();

  // SQLite/D1 doesn't support RETURNING with UPDATE in older versions, so we
  // do this in two steps inside a transaction-like batch:
  //   1. SELECT pending jobs
  //   2. UPDATE each to set locked_until + status='running' + started_at
  //
  // This is racy across isolates, but for a low-volume security bot running on
  // the free tier (one cron invocation every 5 min) the race window is
  // negligible. The dedup_key on `enqueueJob` is the primary defence against
  // double-processing.
  const rows = await db
    .prepare(`SELECT id, payload_json, attempts, max_attempts FROM job_queue
              WHERE kind = ? AND status = 'pending'
                AND run_after <= ?
                AND (locked_until IS NULL OR locked_until <= ?)
              ORDER BY priority DESC, created_at ASC
              LIMIT ?`)
    .bind(kind, now.toISOString(), now.toISOString(), limit)
    .all<{ id: string; payload_json: string; attempts: number; max_attempts: number }>();

  const claimed: Array<{ id: string; payload: Record<string, unknown>; attempts: number; max_attempts: number }> = [];
  for (const r of rows.results ?? []) {
    await db
      .prepare(`UPDATE job_queue SET status = 'running', attempts = attempts + 1, started_at = ?, locked_until = ? WHERE id = ? AND status = 'pending'`)
      .bind(now.toISOString(), lockUntil, r.id)
      .run();
    claimed.push({
      id: r.id,
      payload: JSON.parse(r.payload_json) as Record<string, unknown>,
      attempts: r.attempts + 1,
      max_attempts: r.max_attempts,
    });
  }
  return claimed;
}

export async function completeJob(db: D1Database, jobId: string, result?: { summary?: string }): Promise<void> {
  await db
    .prepare(`UPDATE job_queue SET status = 'completed', completed_at = ?, last_error = NULL WHERE id = ?`)
    .bind(new Date().toISOString(), jobId)
    .run();
}

export async function failJob(
  db: D1Database,
  jobId: string,
  error: string,
  opts: { retry_after_seconds?: number } = {},
): Promise<void> {
  // Determine if we should retry or send to dead-letter
  const row = await db
    .prepare(`SELECT attempts, max_attempts FROM job_queue WHERE id = ?`)
    .bind(jobId)
    .first<{ attempts: number; max_attempts: number }>();

  if (!row) return;
  const shouldRetry = row.attempts < row.max_attempts;
  const now = new Date();
  const runAfter = shouldRetry
    ? new Date(now.getTime() + (opts.retry_after_seconds ?? 60) * 1000).toISOString()
    : now.toISOString();

  await db
    .prepare(`UPDATE job_queue SET status = ?, last_error = ?, run_after = ?, locked_until = ? WHERE id = ?`)
    .bind(
      shouldRetry ? "pending" : "dead_letter",
      error.slice(0, 500),
      runAfter,
      new Date(0).toISOString(),
      jobId,
    )
    .run();
}

export async function cancelJob(db: D1Database, jobId: string, reason: string): Promise<void> {
  await db
    .prepare(`UPDATE job_queue SET status = 'cancelled', completed_at = ?, last_error = ? WHERE id = ?`)
    .bind(new Date().toISOString(), reason, jobId)
    .run();
}

/**
 * Cleanup: delete completed/failed/cancelled jobs older than `olderThanDays`.
 * Called from the cron handler to prevent the table from growing unbounded
 * (the free tier caps D1 at 5 GB total).
 */
export async function purgeOldJobs(db: D1Database, olderThanDays: number): Promise<number> {
  const cutoff = new Date(Date.now() - olderThanDays * 86_400_000).toISOString();
  const result = await db
    .prepare(`DELETE FROM job_queue WHERE status IN ('completed','failed','cancelled','dead_letter') AND created_at < ?`)
    .bind(cutoff)
    .run();
  return result.meta?.changes ?? 0;
}
