// src/cron/handler.ts
// Single Cron Trigger handler (free tier allows exactly one cron per worker).
//
// The cron fires every 5 minutes. Each tick:
//   1. auto-expires jobs that were claimed but never finished (crashed tick);
//   2. dispatches pending Telegram notifications FIRST (cheap, and the operator
//      cares about them before anything else);
//   3. claims and runs up to FREE_TIER_MAX_JOBS_PER_CRON scan jobs;
//   4. enqueues a fresh scan for every active target whose last scan is older
//      than PASSIVE_RESCAN_MINUTES — never every tick;
//   5. once an hour, purges old job_queue rows and old notifications.
//
// All work runs inside the cron invocation (wall-clock bound: the heavy lifting
// is network I/O), and every step is bounded so one slow target cannot starve
// the rest.

import type { Env } from "../env.js";
import { num } from "../env.js";
import { LIMITS } from "../constants.js";
import { log } from "../lib/console-logger.js";
import { randomId } from "../crypto/hash.js";
import { enqueueJob, purgeOldJobs } from "../db/job-queue.js";
import { runPendingScans } from "../queues/scan-runner.js";
import { dispatchPendingNotifications } from "../queues/notification-dispatcher.js";

export async function handleScheduled(
  controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const now = new Date();
  const minuteOfDay = now.getUTCHours() * 60 + now.getUTCMinutes();

  // ---- 1. Stale jobs -----------------------------------------------------
  const stale = await autoExpireStaleJobs(env.DB, now).catch((err) => {
    log.warn("cron.stale_jobs_expire_failed", { err: String(err) });
    return 0;
  });

  // ---- 2. Notifications first -------------------------------------------
  const notifications = await dispatchPendingNotifications(env, ctx).catch((err) => {
    log.warn("cron.dispatch_notifications_failed", { err: String(err) });
    return { claimed: 0, sent: 0, failed: 0, deduplicated: 0 };
  });

  // ---- 3. Scan jobs -----------------------------------------------------
  const scans = await runPendingScans(env, ctx).catch((err) => {
    log.warn("cron.run_scans_failed", { err: String(err) });
    return { claimed: 0, completed: 0, failed: 0, alertsEnqueued: 0 };
  });

  // ---- 4. Schedule the next pass ---------------------------------------
  const enqueued = await enqueueDueScans(env, now).catch((err) => {
    log.warn("cron.enqueue_scans_failed", { err: String(err) });
    return { targets: 0, enqueued: 0 };
  });

  // ---- 5. Hourly retention sweep ---------------------------------------
  let purgedJobs = 0;
  let purgedNotifications = 0;
  if (minuteOfDay % 60 === 0) {
    purgedJobs = await purgeOldJobs(env.DB, LIMITS.JOB_RETENTION_DAYS).catch(() => 0);
    purgedNotifications = await purgeOldNotifications(env.DB, LIMITS.NOTIFICATION_RETENTION_DAYS).catch(() => 0);
  }

  log.info("cron.tick_complete", {
    cron: controller.cron,
    time: now.toISOString(),
    staleJobsExpired: stale,
    notifications,
    scans,
    scansEnqueued: enqueued.enqueued,
    activeTargets: enqueued.targets,
    purgedJobs,
    purgedNotifications,
  });
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/**
 * A job still 'running' after its lock expired belongs to a tick that died
 * mid-flight. Flip it to failed so the retry logic can pick it up again instead
 * of leaving it stuck forever.
 */
async function autoExpireStaleJobs(db: D1Database, now: Date): Promise<number> {
  const result = await db
    .prepare(
      `UPDATE job_queue SET status = 'failed', last_error = 'stale: lock expired before completion', completed_at = ?
        WHERE status = 'running' AND locked_until < ?`,
    )
    .bind(now.toISOString(), now.toISOString())
    .run();
  return result.meta?.changes ?? 0;
}

/**
 * Enqueue a scan for every active target that has not been scanned recently.
 *
 * The throttle is `MAX(created_at)` over the target's `scans` rows (queued or
 * not), which spaces rescans by PASSIVE_RESCAN_MINUTES instead of firing on
 * every 5-minute tick.
 */
export async function enqueueDueScans(
  env: Env,
  now: Date,
): Promise<{ targets: number; enqueued: number }> {
  const rescanMs = num(env.PASSIVE_RESCAN_MINUTES, 30) * 60_000;
  const cutoff = new Date(now.getTime() - rescanMs).toISOString();

  const rows = await env.DB
    .prepare(
      `SELECT t.id, t.organization_id, t.name,
              (SELECT MAX(s.created_at) FROM scans s WHERE s.target_id = t.id) AS last_scan
         FROM targets t
        WHERE t.status = 'active'`,
    )
    .all<{ id: string; organization_id: string; name: string; last_scan: string | null }>();

  const targets = (rows.results ?? []).length;
  let enqueued = 0;

  for (const t of rows.results ?? []) {
    if (t.last_scan && t.last_scan > cutoff) continue; // scanned recently enough

    // The queued `scans` row keeps /list honest AND throttles the next tick.
    const scanId = `scan_${crypto.randomUUID()}`;
    const stamp = now.toISOString();
    await env.DB
      .prepare(
        `INSERT INTO scans (id, organization_id, target_id, trigger, status, requested_by, created_at, updated_at)
         VALUES (?, ?, ?, 'cron', 'queued', NULL, ?, ?)`,
      )
      .bind(scanId, t.organization_id, t.id, stamp, stamp)
      .run();

    const dedupKey = `scan:${t.id}:${stamp.slice(0, 16)}`;
    await enqueueJob(env.DB, "scan", {
      job_id: scanId,
      scan_id: scanId,
      target_id: t.id,
      target_name: t.name,
      organization_id: t.organization_id,
      profile: "passive-only",
      triggered_by: "cron",
      triggered_by_user_id: null,
      request_id: randomId("cron", 8),
      enqueued_at: stamp,
    }, { priority: 1, dedup_key: dedupKey });
    enqueued++;
  }

  return { targets, enqueued };
}

/** Retention: notification history is kept for NOTIFICATION_RETENTION_DAYS. */
async function purgeOldNotifications(db: D1Database, olderThanDays: number): Promise<number> {
  const cutoff = new Date(Date.now() - olderThanDays * 86_400_000).toISOString();
  const result = await db.prepare(`DELETE FROM notifications WHERE created_at < ?`).bind(cutoff).run();
  return result.meta?.changes ?? 0;
}

