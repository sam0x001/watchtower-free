// src/queues/notification-dispatcher.ts
// Synchronous notification dispatcher — replaces the v2 NOTIFY_QUEUE consumer.
//
// Reads pending `notification` jobs from `job_queue`, sends each via the
// configured channel (Telegram, Slack, email, etc.), and marks them sent
// or failed.

import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { sendMessage } from "../telegram/webhook.js";
import { redactSync } from "../security/redaction.js";
import { log as defaultLog } from "../audit/logger.js";
import { sendSlack } from "../notifications/slack.js";
import { sendJira } from "../notifications/jira.js";
import { sendEmail } from "../notifications/email.js";
import { sendGithub } from "../notifications/github.js";
import { sendGenericWebhook } from "../notifications/webhook.js";
import { claimPendingJobs, completeJob, failJob } from "../db/job-queue.js";
import { num } from "../env.js";

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🚨",
  high: "⚠️",
  medium: "📋",
  low: "ℹ️",
  informational: "📌",
};

export async function dispatchPendingNotifications(
  env: Env,
  ctx: ExecutionContext,
): Promise<{ claimed: number; sent: number; failed: number }> {
  const log = defaultLog;
  const maxPerCron = num(env.FREE_TIER_MAX_NOTIFICATIONS_PER_CRON, 10);

  const jobs = await claimPendingJobs(env.DB, "notification", maxPerCron, 60_000);
  let sent = 0;
  let failed = 0;

  for (const job of jobs) {
    ctx.waitUntil((async () => {
      const data = job.payload as unknown as NotificationMessage & { dedup_key?: string };

      // Dedup: if we already sent a notification with this dedup_key in the
      // last 24h, mark this one completed without sending.
      const dedupKey = data.dedup_key ?? job.payload["dedup_key"] as string | undefined;
      if (dedupKey) {
        const existing = await env.DB
          .prepare(`SELECT id FROM notifications WHERE dedupe_key = ? AND status = 'sent' AND created_at > ?`)
          .bind(dedupKey, new Date(Date.now() - 24 * 3600 * 1000).toISOString())
          .first<{ id: string }>();
        if (existing) {
          await completeJob(env.DB, job.id);
          return;
        }
      }

      const id = `notif_${crypto.randomUUID()}`;
      await env.DB
        .prepare(`INSERT INTO notifications (id, organization_id, target_id, finding_id, channel, destination, alert_type, severity, title, body_redacted, dedupe_key, status, attempts, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'scan_alert', ?, ?, ?, ?, 'pending', ?, ?, ?)`)
        .bind(id, data.organization_id, data.target_id ?? null, data.finding_id ?? null, data.channel, data.channel, data.severity, String(data.payload?.title ?? 'Watchtower alert'), JSON.stringify(data.payload), dedupKey ?? `adhoc-${id}`, (job.attempts ?? 1) - 1, new Date().toISOString(), new Date().toISOString())
        .run();

      const { redacted } = redactSync(JSON.stringify(data.payload, null, 2));
      const sanitizedPayload = JSON.parse(redacted) as Record<string, unknown>;
      let didSend = false;
      let lastErr: string | null = null;

      try {
        switch (data.channel) {
          case "telegram": {
            const message = formatTelegramAlert(data.severity, sanitizedPayload);
            const owner = await env.DB
              .prepare(`SELECT u.telegram_user_id FROM users u JOIN memberships m ON m.user_id = u.id JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? AND r.name = 'owner' LIMIT 1`)
              .bind(data.organization_id)
              .first<{ telegram_user_id: string }>();
            if (owner?.telegram_user_id) {
              await sendMessage(env, Number(owner.telegram_user_id), message, { parseMode: "HTML" });
              didSend = true;
            } else {
              lastErr = "no owner telegram_user_id found";
            }
            break;
          }
          case "slack": didSend = await sendSlack(env, data); break;
          case "email": didSend = await sendEmail(env, data); break;
          case "jira": didSend = await sendJira(env, data); break;
          case "github": didSend = await sendGithub(env, data); break;
          case "webhook": didSend = await sendGenericWebhook(env, data); break;
          default: lastErr = `unknown channel: ${data.channel}`;
        }
      } catch (err) {
        lastErr = String(err);
      }

      await env.DB
        .prepare(`UPDATE notifications SET status = ?, last_error = ?, attempts = ?, sent_at = ? WHERE id = ?`)
        .bind(didSend ? "sent" : "failed", lastErr, job.attempts, didSend ? new Date().toISOString() : null, id)
        .run();

      if (didSend) {
        await completeJob(env.DB, job.id);
        sent++;
      } else {
        await failJob(env.DB, job.id, lastErr ?? "unknown", { retry_after_seconds: 30 * job.attempts });
        failed++;
      }
    })());
  }

  return { claimed: jobs.length, sent, failed };
}

function formatTelegramAlert(severity: string, payload: Record<string, unknown>): string {
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
  const footer = `\n\n<i>Use /diff_latest to see all recent changes or /finding_details to inspect a specific finding.</i>`;

  return `${header}${targetLine}${changeLine}${findingLine}${summaryBlock}${footer}`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
