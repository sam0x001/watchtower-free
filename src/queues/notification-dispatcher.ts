// src/queues/notification-dispatcher.ts
// Telegram-only notification dispatcher.
//
// Reads pending `notification` jobs from `job_queue` (written by the scan
// runner and the cron handler), suppresses anything that was already delivered
// for the same dedupe_key inside LIMITS.NOTIFICATION_DEDUPE_WINDOW_HOURS, then
// sends one message per allowlisted Telegram user and marks the job
// sent / failed (a failure is retried with backoff by failJob).

import type { Env } from "../env.js";
import { num } from "../env.js";
import { LIMITS } from "../constants.js";
import type { NotificationMessage, Severity } from "../types.js";
import { sendMessage, resolveAllowlist } from "../telegram/webhook.js";
import { redactSync } from "../security/redaction.js";
import { claimPendingJobs, completeJob, failJob } from "../db/job-queue.js";
import { log } from "../lib/console-logger.js";

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🚨",
  high: "⚠️",
  medium: "📋",
  low: "ℹ️",
  informational: "📌",
};

/** How long a claimed job stays locked while we send it. */
const NOTIFICATION_LOCK_MS = 60_000;

export interface DispatchResult {
  claimed: number;
  sent: number;
  failed: number;
  deduplicated: number;
}

export async function dispatchPendingNotifications(
  env: Env,
  _ctx: ExecutionContext,
): Promise<DispatchResult> {
  const maxPerCron = num(env.FREE_TIER_MAX_NOTIFICATIONS_PER_CRON, 10);
  const jobs = await claimPendingJobs(env.DB, "notification", maxPerCron, NOTIFICATION_LOCK_MS);

  const recipients = (await resolveAllowlist(env)).filter((id) => /^\d+$/.test(id));
  let sent = 0;
  let failed = 0;
  let deduplicated = 0;

  for (const job of jobs) {
    const data = job.payload as unknown as NotificationMessage;
    const dedupeKey = (job.payload["dedup_key"] as string | undefined) ?? `job:${job.id}`;
    const severity: Severity = data.severity ?? "informational";
    const payload = (data.payload ?? {}) as Record<string, unknown>;
    const title = String(payload["title"] ?? "Watchtower alert");

    // ---- Dedup -----------------------------------------------------------
    if (await alreadySent(env.DB, dedupeKey)) {
      await completeJob(env.DB, job.id);
      deduplicated++;
      continue;
    }

    // ---- Record the attempt ---------------------------------------------
    // Only the redacted JSON is ever written down; the alert itself never
    // contains a raw secret value in the first place.
    const notificationId = `notif_${crypto.randomUUID()}`;
    const bodyRedacted = redactSync(JSON.stringify(payload)).redacted.slice(0, 8000);
    await env.DB
      .prepare(
        `INSERT INTO notifications (
           id, organization_id, target_id, finding_id, channel, destination,
           alert_type, severity, title, body_redacted, dedupe_key, status,
           attempts, created_at, updated_at
         ) VALUES (?, ?, ?, ?, 'telegram', ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
      )
      .bind(
        notificationId,
        data.organization_id ?? "default",
        data.target_id ?? null,
        data.finding_id ?? null,
        recipients.join(",") || "none",
        String(payload["change_type"] ?? "alert"),
        severity,
        title.slice(0, 300),
        bodyRedacted,
        dedupeKey,
        job.attempts,
        new Date().toISOString(),
        new Date().toISOString(),
      )
      .run();

    if (recipients.length === 0) {
      await markNotification(env.DB, notificationId, "failed", "no allowlisted Telegram recipients", job.attempts);
      await failJob(env.DB, job.id, "no allowlisted Telegram recipients", { retry_after_seconds: 900 });
      failed++;
      continue;
    }

    // ---- Send ------------------------------------------------------------
    const message = formatTelegramAlert(severity, payload);
    let delivered = 0;
    let lastError: string | null = null;

    for (const chatId of recipients) {
      try {
        await sendMessage(env, Number(chatId), message, { parseMode: "HTML" });
        delivered++;
      } catch (err) {
        lastError = String(err);
        log.warn("notification.send_failed", { chatId, notificationId, err: lastError });
      }
    }

    if (delivered > 0) {
      await markNotification(env.DB, notificationId, "sent", lastError, job.attempts);
      await completeJob(env.DB, job.id);
      sent++;
    } else {
      await markNotification(env.DB, notificationId, "failed", lastError ?? "unknown error", job.attempts);
      await failJob(env.DB, job.id, lastError ?? "unknown error", {
        retry_after_seconds: 60 * Math.max(1, job.attempts),
      });
      failed++;
    }
  }

  return { claimed: jobs.length, sent, failed, deduplicated };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** True when an identical alert was already delivered inside the dedupe window. */
async function alreadySent(db: D1Database, dedupeKey: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - LIMITS.NOTIFICATION_DEDUPE_WINDOW_HOURS * 3_600_000).toISOString();
  const row = await db
    .prepare(`SELECT id FROM notifications WHERE dedupe_key = ? AND status = 'sent' AND created_at > ? LIMIT 1`)
    .bind(dedupeKey, cutoff)
    .first<{ id: string }>();
  return !!row;
}

async function markNotification(
  db: D1Database,
  id: string,
  status: "sent" | "failed",
  error: string | null,
  attempts: number,
): Promise<void> {
  await db
    .prepare(`UPDATE notifications SET status = ?, last_error = ?, attempts = ?, sent_at = ?, updated_at = ? WHERE id = ?`)
    .bind(status, error?.slice(0, 500) ?? null, attempts, status === "sent" ? new Date().toISOString() : null, new Date().toISOString(), id)
    .run();
}

/**
 * Render one alert as Telegram HTML. Kept deliberately plain: a severity
 * header, the target, the change type and the summary body.
 */
export function formatTelegramAlert(severity: string, payload: Record<string, unknown>): string {
  const emoji = SEVERITY_EMOJI[severity] ?? "📌";
  const title = (payload["title"] as string) ?? (payload["change_type"] as string) ?? "Notification";
  const summary = (payload["summary"] as string) ?? "";
  const targetName = (payload["target_name"] as string) ?? null;
  const changeType = (payload["change_type"] as string) ?? null;
  const findingId = (payload["finding_id"] as string) ?? null;

  const header = `${emoji} <b>[${severity.toUpperCase()}] ${escapeHtml(title)}</b>`;
  const targetLine = targetName ? `\n\n<b>Target:</b> ${escapeHtml(targetName)}` : "";
  const changeLine = changeType ? `\n<b>Change type:</b> <code>${escapeHtml(changeType)}</code>` : "";
  const findingLine = findingId ? `\n<b>Finding ID:</b> <code>${escapeHtml(findingId)}</code>` : "";
  const summaryBlock = summary ? `\n\n${escapeHtml(summary)}` : "";

  return `${header}${targetLine}${changeLine}${findingLine}${summaryBlock}`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

