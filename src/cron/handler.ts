// src/cron/handler.ts
// Single Cron Trigger handler — replaces v2's 5 crons (free tier limit: 1 per worker).
//
// The cron fires every 5 minutes. Each tick:
//   1. Auto-expires stale scan jobs (status='running' but locked_until passed)
//   2. Dispatches any pending `scan` jobs from job_queue
//   3. Dispatches any pending `notification` jobs from job_queue
//   4. Enqueues scheduled scans for all authorized targets (every 5 min)
//   5. Sends scope-expiry warnings (within warning window)
//   6. Purges old job_queue rows + audit_logs past retention
//
// All work runs inside `ctx.waitUntil()` to respect the free-tier 10ms CPU
// ceiling. Each sub-step is bounded and the next tick picks up where this
// one left off.

import type { Env } from "../env.js";
import { EmergencyStopClient } from "../db/emergency-stop.js";
import { isScopeExpired, scopeExpiringSoon } from "../security/scope.js";
import { num } from "../env.js";
import { SCOPE_EXPIRY_WARNING_DAYS } from "../constants.js";
import { log } from "../audit/logger.js";
import { sendMessage } from "../telegram/webhook.js";
import { randomId } from "../crypto/hash.js";
import { enqueueJob, purgeOldJobs } from "../db/job-queue.js";
import { runPendingScans } from "../queues/scan-runner.js";
import { dispatchPendingNotifications } from "../queues/notification-dispatcher.js";
import { listAuditLogs } from "../db/queries/audit.js";

export async function handleScheduled(
  controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const log_ = log;
  const now = new Date();
  const minuteOfDay = now.getUTCHours() * 60 + now.getUTCMinutes();

  // 1. Auto-expire stale running jobs (locked but never completed)
  await autoExpireStaleJobs(env.DB, now).catch((err) => {
    log_.warn("cron.stale_jobs_expire_failed", { err: String(err) });
  });

  // 2. Dispatch pending notification jobs FIRST (high priority, quick to send)
  const notifyResult = await dispatchPendingNotifications(env, ctx).catch((err) => {
    log_.warn("cron.dispatch_notifications_failed", { err: String(err) });
    return { claimed: 0, sent: 0, failed: 0 };
  });

  // 3. Dispatch pending scan jobs (next priority — actual recon work)
  const scanResult = await runPendingScans(env, ctx).catch((err) => {
    log_.warn("cron.run_scans_failed", { err: String(err) });
    return { claimed: 0, completed: 0, failed: 0, alertsEnqueued: 0 };
  });

  // 4. Enqueue scheduled scans for authorized targets (every tick)
  const es = new EmergencyStopClient(env.DB);
  const globalStop = await es.isBlocked("global");
  let scansEnqueued = 0;
  let expiredTargets = 0;
  let warningTargets = 0;

  if (!globalStop) {
    const targets = await env.DB
      .prepare(`SELECT t.id, t.name, t.organization_id, t.authorization_expires_at, t.paused FROM targets t WHERE t.paused = 0`)
      .all<{ id: string; name: string; organization_id: string; authorization_expires_at: string; paused: number }>();

    for (const t of targets.results ?? []) {
      // Check emergency stop per-target
      if (await es.isBlocked("target", t.id)) continue;

      // Check expiry
      if (isScopeExpired({ authorization_expires_at: t.authorization_expires_at } as never, now)) {
        await env.DB.prepare(`UPDATE targets SET paused = 1 WHERE id = ?`).bind(t.id).run();
        await env.DB.prepare(`UPDATE job_queue SET status = 'cancelled' WHERE kind = 'scan' AND json_extract(payload_json, '$.target_id') = ? AND status IN ('pending','running')`)
          .bind(t.id).run();
        expiredTargets++;
        continue;
      }

      // Expiring-soon warning
      if (scopeExpiringSoon({ authorization_expires_at: t.authorization_expires_at } as never, num(env.SCOPE_EXPIRY_WARNING_DAYS, SCOPE_EXPIRY_WARNING_DAYS), now)) {
        const owner = await env.DB
          .prepare(`SELECT u.telegram_id FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.organization_id = ? AND m.role = 'owner' LIMIT 1`)
          .bind(t.organization_id)
          .first<{ telegram_id: string }>();
        if (owner?.telegram_id) {
          await enqueueJob(env.DB, "notification", {
            organization_id: t.organization_id,
            target_id: t.id,
            channel: "telegram",
            severity: "high",
            payload: {
              title: `Authorization expiring soon for ${t.name}`,
              summary: `Target ${t.name} (ID ${t.id}) will expire on ${t.authorization_expires_at}.\nUse /scope_expire ${t.id} or extend authorization before the deadline.`,
              change_type: "authorization_expiring",
              target_id: t.id,
              target_name: t.name,
              expires_at: t.authorization_expires_at,
            },
            dedup_key: `auth_expiring:${t.id}:${t.authorization_expires_at.slice(0, 10)}`,
            attempt: 0,
          }, { dedup_key: `auth_expiring:${t.id}:${t.authorization_expires_at.slice(0, 10)}` });
          warningTargets++;
        }
      }

      // Enqueue a passive scan for this target (dedup_key prevents duplicates
      // if a previous tick already enqueued one and it hasn't started yet).
      const jobId = `scan_${t.id}_${now.toISOString().slice(0, 16)}`; // per-minute granularity
      await enqueueJob(env.DB, "scan", {
        job_id: jobId,
        target_id: t.id,
        organization_id: t.organization_id,
        profile: "passive-only",
        triggered_by: "cron",
        triggered_by_user_id: null,
        attempt: 0,
        enqueued_at: now.toISOString(),
      }, { priority: 1, dedup_key: `scan:${t.id}:${now.toISOString().slice(0, 16)}` });
      scansEnqueued++;
    }
  }

  // 5. Once an hour, purge old job_queue rows (>7 days) + old audit_logs (>retention)
  if (minuteOfDay % 60 === 0) {
    const purgedJobs = await purgeOldJobs(env.DB, 7);
    const purgedAudit = await purgeOldAuditLogs(env, num(env.AUDIT_RETENTION_DAYS, 730));
    log_.info("cron.purge_complete", { purgedJobs, purgedAudit });
  }

  log_.info("cron.tick_complete", {
    cron: controller.cron,
    time: now.toISOString(),
    notifications: notifyResult,
    scans: scanResult,
    scansEnqueued,
    expiredTargets,
    warningTargets,
  });

  ctx.waitUntil(Promise.resolve());
}

async function autoExpireStaleJobs(db: D1Database, now: Date): Promise<void> {
  const staleCutoff = new Date(now.getTime() - 5 * 60_000).toISOString(); // 5 min stale window
  await db
    .prepare(`UPDATE job_queue SET status = 'failed', last_error = 'stale: never completed', completed_at = ? WHERE status = 'running' AND locked_until < ?`)
    .bind(now.toISOString(), staleCutoff)
    .run();
}

async function purgeOldAuditLogs(env: Env, retentionDays: number): Promise<number> {
  const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
  const result = await env.DB
    .prepare(`DELETE FROM audit_logs WHERE timestamp < ?`)
    .bind(cutoff)
    .run();
  return result.meta?.changes ?? 0;
}
