// src/telegram/commands.ts
// Command router for Telegram. Implements all 44 commands listed in the spec.

import type { Env } from "../env.js";
import type { ConsoleLogger, D1AuditLogger } from "../audit/logger.js";
import { sendMessage } from "./webhook.js";
import { messages } from "./messages.js";
import { EmergencyStopClient } from "../db/emergency-stop.js";
import { enqueueJob, cancelJob } from "../db/job-queue.js";
import { randomId, sha256 } from "../crypto/hash.js";
import { ensureUserId, findUserIdByTelegram, resolveRoleId, targetContext } from "../db/queries/identity.js";

interface CommandContext {
  text: string;
  chatId: number;
  user: { id: number; first_name?: string; username?: string } | null;
  requestId: string;
  audit: D1AuditLogger;
  log: ConsoleLogger;
}

// Telegram uses `/cmd_arg_arg` (we registered commands as e.g. "scope_add").
// However the bot also accepts `/scope add` (multi-word) — normalize both forms.
function parseCommand(text: string): { command: string; args: string[] } {
  const trimmed = text.trim().replace(/^@\w+\s+/, "").replace(/^\//, "");
  const [first, ...rest] = trimmed.split(/\s+/);
  if (!first) return { command: "help", args: [] };

  // Accept slash-synonyms like "/scope_add" or "/scope add"
  const underscored = first.toLowerCase().replace(/-/g, "_");
  const knownMulti = new Set([
    "scope", "target", "scan", "findings", "finding", "report", "diff",
    "alerts", "schedule", "integration", "team",
  ]);
  if (knownMulti.has(underscored) && rest.length > 0) {
    const sub = rest[0]!.toLowerCase().replace(/-/g, "_");
    return { command: `${underscored}_${sub}`, args: rest.slice(1) };
  }
  return { command: underscored, args: rest };
}

export async function handleCommand(env: Env, ctx: CommandContext): Promise<void> {
  const { command, args } = parseCommand(ctx.text);
  const handler = handlers[command] ?? handlers["help"]!;
  await ctx.audit.log({
    timestamp: new Date().toISOString(),
    user_id: null,
    telegram_id: ctx.user ? String(ctx.user.id) : null,
    organization_id: null,
    action: `telegram.command.${command}`,
    target_id: args[0] ?? null,
    scope_id: null,
    job_id: null,
    scanner: null,
    args_redacted: JSON.stringify({ args }),
    result: "success",
    error: null,
    ip: null,
    request_id: ctx.requestId,
  });

  try {
    await handler(env, ctx, args);
  } catch (err) {
    ctx.log.error(`telegram.command.${command}.failed`, { err: String(err), requestId: ctx.requestId });
    await sendMessage(env, ctx.chatId, `❌ Command failed: ${String(err)}`);
  }
}

type CommandHandler = (env: Env, ctx: CommandContext, args: string[]) => Promise<void>;

/**
 * Canonical alert toggling. Alerting is modelled as per-target notification
 * preferences (`notification_preferences`), not a JSON blob on the target row.
 */
async function setTargetAlerts(env: Env, targetId: string, enabled: boolean): Promise<void> {
  const target = await targetContext(env.DB, targetId);
  if (!target) return;
  const now = new Date().toISOString();
  const existing = await env.DB
    .prepare(`SELECT id FROM notification_preferences WHERE organization_id = ? AND target_id = ? AND channel = 'telegram' LIMIT 1`)
    .bind(target.organization_id, targetId)
    .first<{ id: string }>();
  if (existing) {
    await env.DB
      .prepare(`UPDATE notification_preferences SET enabled = ?, updated_at = ? WHERE id = ?`)
      .bind(enabled ? 1 : 0, now, existing.id)
      .run();
    return;
  }
  await env.DB
    .prepare(`INSERT INTO notification_preferences (
        id, organization_id, target_id, user_id, channel, destination, enabled,
        min_severity, immediate_types, quiet_hours_utc, digest_frequency, created_at, updated_at
      ) VALUES (?, ?, ?, NULL, 'telegram', NULL, ?, 'low', '[]', NULL, 'immediate', ?, ?)`)
    .bind(randomId("npref", 12), target.organization_id, targetId, enabled ? 1 : 0, now, now)
    .run();
}

const handlers: Record<string, CommandHandler> = {
  start: async (env, ctx) => {
    await sendMessage(env, ctx.chatId, messages.welcome(ctx.user?.first_name ?? "operator"), { parseMode: "HTML" });
  },
  help: async (env, ctx) => {
    await sendMessage(env, ctx.chatId, messages.help(), { parseMode: "HTML" });
  },
  authorize: async (env, ctx, args) => {
    if (args.length < 2) {
      await sendMessage(env, ctx.chatId, "Usage: /authorize <target_name> <authorization_reference>\nExample: /authorize example.com WRITTEN-CONTRACT-2026-001");
      return;
    }
    const targetName = args[0]!;
    const reference = args.slice(1).join(" ");
    const createdBy = await ensureUserId(env.DB, ctx.user);
    if (!createdBy) { await sendMessage(env, ctx.chatId, "⛔ Cannot resolve your user record. Send /start first."); return; }
    // Resolve the operator's organization from their membership; fall back to the
    // bootstrap 'ORG_main' org documented in DEPLOYMENT.md so the FK is satisfied.
    const orgRow = await env.DB
      .prepare(`SELECT organization_id FROM memberships WHERE user_id = ? AND status = 'active' LIMIT 1`)
      .bind(createdBy)
      .first<{ organization_id: string }>();
    const orgId = orgRow?.organization_id ?? "ORG_main";
    const targetId = randomId("TGT", 8);
    const now = new Date().toISOString();
    const validUntil = new Date(Date.now() + 365 * 86_400_000).toISOString();
    try {
      await env.DB
        .prepare(
          `INSERT INTO targets (
             id, organization_id, name, program_handle, criticality, data_sensitivity,
             internet_exposed, status, authorization_status, authorization_type,
             authorization_ref, valid_from, valid_until, passive_only, low_impact_active,
             intrusive_enabled, human_approval_required, max_requests_per_minute,
             max_concurrent_jobs, scan_profile, created_by, created_at, updated_at
           ) VALUES (?, ?, ?, ?, 'medium', 'internal', 1, 'active', 'confirmed',
             'bug_bounty_program', ?, ?, ?, 1, 0, 0, 1, 60, 1, 'passive-only', ?, ?, ?)`,
        )
        .bind(targetId, orgId, targetName, reference, reference, now, validUntil, createdBy, now, now)
        .run();
    } catch (err) {
      await sendMessage(env, ctx.chatId, `❌ Target not created: ${String(err)}`);
      return;
    }
    await ctx.audit.log({
      timestamp: new Date().toISOString(),
      user_id: null,
      telegram_id: ctx.user ? String(ctx.user.id) : null,
      organization_id: null,
      action: "telegram.authorize",
      target_id: targetId,
      scope_id: null,
      job_id: null,
      scanner: null,
      args_redacted: JSON.stringify({ target_name: targetName, reference }),
      result: "success",
      error: null,
      ip: null,
      request_id: ctx.requestId,
    });
    await sendMessage(env, ctx.chatId, `✅ Authorization recorded for ${targetName}.\nReference: ${reference}\nTarget ID: ${targetId}\n\nNext step — run:\n/scope_add ${targetId} domain ${targetName}`);
  },
  scope_add: async (env, ctx, args) => {
    if (args.length < 2) {
      await sendMessage(env, ctx.chatId, "Usage: /scope_add <target_id> <type:domain|wildcard_domain|ip|cidr|url|api> <value> [--exclude]\nExample: /scope_add TGT_abc domain example.com");
      return;
    }
    const [targetIdOrName, type, ...rest] = args;
    const exclude = rest.includes("--exclude");
    const value = rest.filter((a) => a !== "--exclude").join(" ");
    const target = await targetContext(env.DB, targetIdOrName!);
    if (!target) { await sendMessage(env, ctx.chatId, "Target not found. Run /target_list <org_id> to see IDs, or use the target name (e.g. rapyd.com)."); return; }
    const targetId = target.id;
    const createdBy = await ensureUserId(env.DB, ctx.user);
    if (!createdBy) { await sendMessage(env, ctx.chatId, "⛔ Cannot resolve your user record. Send /start first."); return; }
    const id = randomId("scope", 12);
    const now = new Date().toISOString();
    try {
      await env.DB
        .prepare(
          `INSERT INTO scopes (
             id, organization_id, target_id, scope_type, value, display_value, status,
             is_primary, is_denylist, include_subdomains, notes,
             valid_from, valid_until, created_by, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, 'active', 0, ?, 1, NULL, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id, target.organization_id, target.id, type, value, value,
          exclude ? 1 : 0,
          target.valid_from, target.valid_until, createdBy, now, now,
        )
        .run();
    } catch (err) {
      await sendMessage(env, ctx.chatId, `❌ Scope not added: ${String(err)}`);
      return;
    }
    await sendMessage(env, ctx.chatId, `✅ Scope entry added: ${type} ${value} (${exclude ? "denylist" : "allowlist"})\nID: ${id}`);
  },
  scope_list: async (env, ctx, args) => {
    const targetId = args[0];
    if (!targetId) { await sendMessage(env, ctx.chatId, "Usage: /scope_list <target_id>"); return; }
    const rows = await env.DB
      .prepare(`SELECT id, scope_type, value, is_denylist, status, valid_until FROM scopes WHERE target_id = ? AND status != 'removed' ORDER BY is_denylist ASC, created_at DESC`)
      .bind(targetId)
      .all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["is_denylist"] ? "🚫" : "✅"} [${r["scope_type"]}] ${r["value"]}  ${r["status"] === "active" ? "" : `(${r["status"]})`}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Scope for ${targetId}:\n\n${lines.join("\n")}` : "No scope entries yet.");
  },
  scope_update: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /scope_update <scope_id> <new_value>"); return; }
    const [scopeId, value] = args;
    await env.DB.prepare(`UPDATE scopes SET value = ?, display_value = ?, updated_at = ? WHERE id = ?`).bind(value, value, new Date().toISOString(), scopeId).run();
    await sendMessage(env, ctx.chatId, `✅ Scope ${scopeId} updated to ${value}`);
  },
  scope_remove: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scope_remove <scope_id>"); return; }
    await env.DB.prepare(`UPDATE scopes SET status = 'removed', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `🗑 Removed scope entry ${args[0]}`);
  },
  scope_pause: async (env, ctx, args) => {
    const now = new Date().toISOString();
    const by = await ensureUserId(env.DB, ctx.user);
    await env.DB.prepare(`UPDATE scopes SET status = 'paused', paused_at = ?, paused_by = ?, updated_at = ? WHERE id = ?`).bind(now, by, now, args[0]).run();
    await sendMessage(env, ctx.chatId, `⏸ Paused scope ${args[0]}`);
  },
  scope_resume: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE scopes SET status = 'active', paused_at = NULL, paused_by = NULL, updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `▶️ Resumed scope ${args[0]}`);
  },
  scope_expire: async (env, ctx, args) => {
    const now = new Date().toISOString();
    await env.DB.prepare(`UPDATE scopes SET status = 'expired', expired_at = ?, valid_until = ?, updated_at = ? WHERE id = ?`).bind(now, now, now, args[0]).run();
    await sendMessage(env, ctx.chatId, `⌛ Marked scope ${args[0]} as expired`);
  },
  target_add: async (env, ctx, args) => {
    if (args.length < 3) {
      await sendMessage(env, ctx.chatId, "Usage: /target_add <org_id> <name> <authorization_expires_at:YYYY-MM-DD> [program_url]");
      return;
    }
    const [orgId, name, expiresAt, programUrl] = args;
    const createdBy = await ensureUserId(env.DB, ctx.user);
    if (!createdBy) { await sendMessage(env, ctx.chatId, "⛔ Cannot resolve your user record. Send /start first."); return; }
    const id = randomId("tgt", 12);
    const now = new Date().toISOString();
    const validUntil = /^\d{4}-\d{2}-\d{2}$/.test(expiresAt ?? "") ? `${expiresAt}T23:59:59.000Z` : (expiresAt as string);
    try {
      await env.DB
        .prepare(
          `INSERT INTO targets (
             id, organization_id, name, program_handle, criticality, data_sensitivity,
             internet_exposed, status, authorization_status, authorization_type,
             authorization_ref, valid_from, valid_until, passive_only, low_impact_active,
             intrusive_enabled, human_approval_required, max_requests_per_minute,
             max_concurrent_jobs, scan_profile, created_by, created_at, updated_at
           ) VALUES (?, ?, ?, ?, 'medium', 'internal', 1, 'active', 'confirmed',
             'bug_bounty_program', ?, ?, ?, 1, 0, 0, 1, 60, 3, 'passive-only', ?, ?, ?)`,
        )
        .bind(id, orgId, name, programUrl ?? null, `telegram:${ctx.user?.id ?? "unknown"}`, now, validUntil, createdBy, now, now)
        .run();
    } catch (err) {
      await sendMessage(env, ctx.chatId, `❌ Target not created: ${String(err)}`);
      return;
    }
    await sendMessage(env, ctx.chatId, `✅ Target created.\nID: ${id}\nName: ${name}\nExpires: ${validUntil}`);
  },
  target_list: async (env, ctx, args) => {
    const orgId = args[0];
    if (!orgId) { await sendMessage(env, ctx.chatId, "Usage: /target_list <org_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, name, status, valid_until FROM targets WHERE organization_id = ?`).bind(orgId).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["status"] === "active" ? "🟢" : "⏸"} ${r["id"]} — ${r["name"]} (${r["status"]}, expires ${r["valid_until"]})`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Targets:\n\n${lines.join("\n")}` : "No targets yet.");
  },
  target_details: async (env, ctx, args) => {
    const r = await env.DB.prepare(`SELECT * FROM targets WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Target not found"); return; }
    await sendMessage(env, ctx.chatId, `🎯 ${r["name"]}\nID: ${r["id"]}\nOrg: ${r["organization_id"]}\nStatus: ${r["status"]}\nPassive only: ${r["passive_only"]}\nLow-impact active: ${r["low_impact_active"]}\nMax r/min: ${r["max_requests_per_minute"]}\nMax concurrent: ${r["max_concurrent_jobs"]}\nAuthorization: ${r["authorization_status"]} (${r["valid_from"]} → ${r["valid_until"]})\nPaused at: ${r["paused_at"] ?? "n/a"}`);
  },
  target_pause: async (env, ctx, args) => {
    const now = new Date().toISOString();
    const by = await ensureUserId(env.DB, ctx.user);
    await env.DB.prepare(`UPDATE targets SET status = 'paused', paused_at = ?, paused_by = ?, updated_at = ? WHERE id = ?`).bind(now, by, now, args[0]).run();
    await sendMessage(env, ctx.chatId, "⏸ Target paused");
  },
  target_resume: async (env, ctx, args) => {
    const now = new Date().toISOString();
    await env.DB.prepare(`UPDATE targets SET status = 'active', paused_at = NULL, paused_by = NULL, updated_at = ? WHERE id = ?`).bind(now, args[0]).run();
    await sendMessage(env, ctx.chatId, "▶️ Target resumed");
  },
  scan_passive: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_passive <target_id>"); return; }
    const targetId = args[0]!;
    // Check emergency stop first
    const es = new EmergencyStopClient(env.DB);
    if (await es.isBlocked("target", targetId)) { await sendMessage(env, ctx.chatId, "⛔ Emergency stop is active for this target. Use /resume after resolving."); return; }
    const target = await targetContext(env.DB, targetId);
    if (!target) { await sendMessage(env, ctx.chatId, "Target not found"); return; }
    const requestedBy = await ensureUserId(env.DB, ctx.user);
    const jobId = randomId("scan", 12);
    const now = new Date().toISOString();
    // Canonical scans row: scope_snapshot/scope_hash are NOT NULL, and the row
    // records how the scan was triggered + which mode it may run in.
    const snapshotRows = await env.DB
      .prepare(`SELECT id, scope_type, value, is_denylist, include_subdomains FROM scopes WHERE target_id = ? AND status = 'active' ORDER BY id ASC`)
      .bind(targetId)
      .all<Record<string, unknown>>();
    const scopeSnapshot = JSON.stringify(snapshotRows.results ?? []);
    const scopeHash = await sha256(scopeSnapshot);
    await env.DB
      .prepare(`INSERT INTO scans (
          id, organization_id, target_id, scope_snapshot, scope_hash, profile, mode,
          trigger, status, requested_by, correlation_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'passive-only', 'passive', 'manual', 'queued', ?, ?, ?, ?)`)
      .bind(jobId, target.organization_id, targetId, scopeSnapshot, scopeHash, requestedBy, ctx.requestId, now, now)
      .run();
    await enqueueJob(env.DB, "scan", {
      job_id: jobId, target_id: targetId,
      organization_id: target.organization_id,
      profile: "passive-only", triggered_by: "telegram", triggered_by_user_id: requestedBy,
      attempt: 0, enqueued_at: now,
    }, { dedup_key: `scan:${targetId}:${now.slice(0, 16)}` });
    await sendMessage(env, ctx.chatId, `🟢 Passive scan queued.\nScan ID: ${jobId}\nRuns within ~5 minutes (next cron tick). Use /scan_status ${jobId} to track.`);
  },
  scan_active: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_active <target_id> [confirm]\n⚠️ Requires explicit human approval. Add 'confirm' as second arg to proceed."); return; }
    if (args[1] !== "confirm") { await sendMessage(env, ctx.chatId, "⚠️ Active scans require human approval.\nRe-run with: /scan_active <target_id> confirm"); return; }
    const targetId = args[0]!;
    await env.DB.prepare(`UPDATE targets SET low_impact_active = 1, updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), targetId).run();
    await sendMessage(env, ctx.chatId, "⚠️ Low-impact active scans enabled. Passive baseline will run first; intrusive checks remain blocked unless separately approved.");
  },
  scan_status: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_status <scan_id>"); return; }
    const r = await env.DB.prepare(`SELECT * FROM scans WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Scan not found"); return; }
    await sendMessage(env, ctx.chatId, `Scan ${r["id"]}\nStatus: ${r["status"]}\nMode: ${r["mode"]}\nProfile: ${r["profile"]}\nTrigger: ${r["trigger"]}\nCreated: ${r["created_at"]}\nStarted: ${r["started_at"] ?? "n/a"}\nFinished: ${r["finished_at"] ?? "n/a"}\nAssets seen: ${r["assets_seen"]}\nErrors: ${r["errors_json"]}`);
  },
  scan_cancel: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_cancel <scan_id>"); return; }
    const jobId = args[0]!;
    const es = new EmergencyStopClient(env.DB);
    await es.cancelJob(jobId, ctx.user ? String(ctx.user.id) : null, "telegram.cancel");
    await cancelJob(env.DB, jobId, "telegram.cancel");
    const now = new Date().toISOString();
    await env.DB
      .prepare(`UPDATE scans SET status = 'cancelled', finished_at = ?, stop_reason = 'telegram.cancel', updated_at = ? WHERE id = ?`)
      .bind(now, now, jobId)
      .run();
    await sendMessage(env, ctx.chatId, `🛑 Scan ${jobId} cancelled.`);
  },
  scan_history: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_history <target_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, profile, status, created_at FROM scans WHERE target_id = ? ORDER BY created_at DESC LIMIT 20`).bind(args[0]).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["status"]} ${r["id"]} (${r["profile"]}) @ ${r["created_at"]}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Scan history:\n\n${lines.join("\n")}` : "No scans yet.");
  },
  findings_list: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /findings_list <org_id> [status] [severity]"); return; }
    const orgId = args[0]!;
    const status = args[1];
    const severity = args[2];
    const where: string[] = ["organization_id = ?"];
    const binds: (string | number)[] = [orgId];
    if (status) { where.push("status = ?"); binds.push(status); }
    if (severity) { where.push("severity = ?"); binds.push(severity); }
    const rows = await env.DB.prepare(`SELECT id, severity, title, status FROM findings WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT 20`).bind(...binds).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `[${(r["severity"] as string).toUpperCase()}] ${r["id"]} — ${r["title"]} (${r["status"]})`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Findings:\n\n${lines.join("\n")}` : "No findings yet.");
  },
  finding_details: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /finding_details <finding_id>"); return; }
    const r = await env.DB.prepare(`SELECT * FROM findings WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Finding not found"); return; }
    await sendMessage(env, ctx.chatId, `[${(r["severity"] as string).toUpperCase()}] ${r["title"]}\n\n${r["summary"]}\n\nSeverity: ${r["severity"]}\nStatus: ${r["status"]}\nConfidence: ${r["confidence"]}\nDetection: ${r["detection_source"]}\nAffected: ${r["affected_url"] ?? "n/a"}`);
  },
  finding_verify: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /finding_verify <finding_id>"); return; }
    // Canonical status values: triaged/in_progress/resolved/closed/... ('in_review' is not valid).
    await env.DB.prepare(`UPDATE findings SET verification_state = 'verified', status = 'triaged', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `✅ Finding ${args[0]} marked as verified.`);
  },
  finding_reject: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /finding_reject <finding_id>"); return; }
    await env.DB.prepare(`UPDATE findings SET verification_state = 'false_positive', status = 'closed', closed_at = ?, updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `🚫 Finding ${args[0]} rejected as false positive.`);
  },
  finding_assign: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /finding_assign <finding_id> <user_id|telegram_id>"); return; }
    // assigned_user_id is a foreign key into users(id); accept either form.
    const assignee = (await findUserIdByTelegram(env.DB, args[1]!))
      ?? (await env.DB.prepare(`SELECT id FROM users WHERE id = ?`).bind(args[1]).first<{ id: string }>())?.id
      ?? null;
    if (!assignee) { await sendMessage(env, ctx.chatId, `User ${args[1]} not found (expected a users.id or telegram id).`); return; }
    await env.DB.prepare(`UPDATE findings SET assigned_user_id = ?, status = 'triaged', updated_at = ? WHERE id = ?`).bind(assignee, new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `📌 Finding ${args[0]} assigned to ${args[1]}.`);
  },
  finding_close: async (env, ctx, args) => {
    const now = new Date().toISOString();
    await env.DB.prepare(`UPDATE findings SET status = 'closed', closed_at = ?, updated_at = ? WHERE id = ?`).bind(now, now, args[0]).run();
    await sendMessage(env, ctx.chatId, `✅ Finding ${args[0]} closed.`);
  },
  finding_reopen: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE findings SET status = 'open', verification_state = 'detected', resolved_at = NULL, closed_at = NULL, updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `↩️ Finding ${args[0]} reopened.`);
  },
  report_create: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /report_create <target_id> <format:markdown|json|pdf|hackerone|bugcrowd|internal|executive>"); return; }
    const [targetId, formatArg] = args as [string, string];
    const target = await targetContext(env.DB, targetId);
    if (!target) { await sendMessage(env, ctx.chatId, "Target not found"); return; }
    const generatedBy = await ensureUserId(env.DB, ctx.user);
    // Canonical reports separate report_type (who it is for) from format
    // (markdown|json|pdf), so map the friendly aliases onto both.
    const mapping: Record<string, { kind: string; format: string }> = {
      markdown: { kind: "internal_pentest", format: "markdown" },
      json: { kind: "internal_pentest", format: "json" },
      pdf: { kind: "internal_pentest", format: "pdf" },
      internal: { kind: "internal_pentest", format: "markdown" },
      hackerone: { kind: "hackerone", format: "markdown" },
      bugcrowd: { kind: "bugcrowd", format: "markdown" },
      executive: { kind: "executive_summary", format: "markdown" },
      asset_inventory: { kind: "asset_inventory", format: "json" },
    };
    const chosen = mapping[formatArg.toLowerCase()] ?? { kind: "internal_pentest", format: "markdown" };
    const id = randomId("rep", 12);
    const now = new Date().toISOString();
    await env.DB
      .prepare(`INSERT INTO reports (
          id, report_ref, organization_id, target_id, report_type, format, title,
          status, generated_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`)
      .bind(
        id, `RPT-${id}`, target.organization_id, targetId, chosen.kind, chosen.format,
        `Watchtower ${chosen.kind.replace(/_/g, " ")} for ${targetId}`, generatedBy, now, now,
      )
      .run();
    await enqueueJob(env.DB, "notification", {
      organization_id: target.organization_id, target_id: targetId, channel: "telegram", severity: "informational", payload: { report_id: id, format: chosen.format }, dedup_key: `report:${id}`, attempt: 0,
    }, { dedup_key: `report:${id}` });
    await sendMessage(env, ctx.chatId, `📄 Report ${id} queued for generation (${chosen.format}).`);
  },
  report_export: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /report_export <report_id|report_ref>"); return; }
    const r = await env.DB
      .prepare(`SELECT id, report_ref, report_type, format, status, created_at, finding_ids, r2_key FROM reports WHERE id = ? OR report_ref = ? LIMIT 1`)
      .bind(args[0], args[0])
      .first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Report not found"); return; }
    let findingCount = 0;
    try { findingCount = (JSON.parse(String(r["finding_ids"] ?? "[]")) as unknown[]).length; } catch { findingCount = 0; }
    await sendMessage(env, ctx.chatId, `📄 Report ${r["report_ref"]}\nType: ${r["report_type"]}\nFormat: ${r["format"]}\nStatus: ${r["status"]}\nCreated: ${r["created_at"]}\nFindings: ${findingCount}\nR2 key: ${r["r2_key"] ?? "pending"}`);
  },
  diff_latest: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /diff_latest <target_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, change_type, severity, created_at FROM changes WHERE target_id = ? ORDER BY created_at DESC LIMIT 20`).bind(args[0]).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `[${(r["severity"] as string).toUpperCase()}] ${r["change_type"]} (${r["id"]}) @ ${r["created_at"]}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Latest changes:\n\n${lines.join("\n")}` : "No changes detected yet.");
  },
  diff_compare: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /diff_compare <target_id> <older_scan_id> <newer_scan_id>"); return; }
    await sendMessage(env, ctx.chatId, `🔍 Diff requested (target=${args[0]}, older=${args[1]}, newer=${args[2] ?? "latest"}). Use the API to retrieve the full diff.`);
  },
  alerts_enable: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /alerts_enable <target_id>"); return; }
    await setTargetAlerts(env, args[0]!, true);
    await sendMessage(env, ctx.chatId, "🔔 Alerts enabled.");
  },
  alerts_disable: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /alerts_disable <target_id>"); return; }
    await setTargetAlerts(env, args[0]!, false);
    await sendMessage(env, ctx.chatId, "🔕 Alerts disabled.");
  },
  schedule_add: async (env, ctx, args) => {
    if (args.length < 3) { await sendMessage(env, ctx.chatId, "Usage: /schedule_add <target_id> <cron_expr> <profile>"); return; }
    const [targetIdOrName, cronExpr, profile] = args as [string, string, string];
    const target = await targetContext(env.DB, targetIdOrName);
    if (!target) { await sendMessage(env, ctx.chatId, "Target not found. Run /target_list <org_id> to see IDs, or use the target name."); return; }
    const targetId = target.id;
    const createdBy = await ensureUserId(env.DB, ctx.user);
    if (!createdBy) { await sendMessage(env, ctx.chatId, "⛔ Cannot resolve your user record. Send /start first."); return; }
    const id = randomId("sch", 12);
    const now = new Date().toISOString();
    await env.DB
      .prepare(`INSERT INTO schedules (
          id, organization_id, target_id, name, profile, mode, frequency, cron_expression,
          jitter_seconds, timezone, enabled, requires_approval, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'passive', 'custom', ?, 5, 'UTC', 1, 0, ?, ?, ?)`)
      .bind(id, target.organization_id, targetId, `Schedule ${id}`, profile, cronExpr, createdBy, now, now)
      .run();
    await sendMessage(env, ctx.chatId, `📅 Schedule added.\nID: ${id}\nCron: ${cronExpr}\nProfile: ${profile}`);
  },
  schedule_list: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /schedule_list <target_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, cron_expression, profile, enabled, last_run_at, next_run_at FROM schedules WHERE target_id = ?`).bind(args[0]).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["enabled"] ? "🟢" : "⏸"} ${r["id"]} — ${r["cron_expression"] ?? "n/a"} (${r["profile"]}) next=${r["next_run_at"] ?? "n/a"}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Schedules:\n\n${lines.join("\n")}` : "No schedules.");
  },
  schedule_remove: async (env, ctx, args) => {
    await env.DB.prepare(`DELETE FROM schedules WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, `🗑 Removed schedule ${args[0]}`);
  },
  integration_add: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /integration_add <org_id> <type:slack|jira|github|email|webhook> [config_json]"); return; }
    const [orgId, type, ...rest] = args;
    const config = rest.join(" ") || "{}";
    const createdBy = await ensureUserId(env.DB, ctx.user);
    if (!createdBy) { await sendMessage(env, ctx.chatId, "⛔ Cannot resolve your user record. Send /start first."); return; }
    // Canonical column is `kind`, with a constrained vocabulary.
    const kindMap: Record<string, string> = {
      slack: "slack", jira: "jira", github: "github", email: "email",
      webhook: "generic_webhook", generic_webhook: "generic_webhook",
      pagerduty: "pagerduty", teams: "teams", splunk: "splunk",
    };
    const kind = kindMap[(type ?? "").toLowerCase()] ?? "generic_webhook";
    const id = randomId("int", 12);
    const now = new Date().toISOString();
    try {
      await env.DB
        .prepare(`INSERT INTO integrations (id, organization_id, kind, name, config_json, enabled, created_by, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`)
        .bind(id, orgId, kind, `${kind} integration`, config, createdBy, now, now)
        .run();
    } catch (err) {
      await sendMessage(env, ctx.chatId, `❌ Integration not added: ${String(err)}`);
      return;
    }
    await sendMessage(env, ctx.chatId, `🔌 Integration added (${kind}). ID: ${id}`);
  },
  integration_remove: async (env, ctx, args) => {
    await env.DB.prepare(`DELETE FROM integrations WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, `🗑 Removed integration ${args[0]}`);
  },
  settings: async (env, ctx) => {
    await sendMessage(env, ctx.chatId, `⚙️ Watchtower Settings\n\nENV: ${env.WATCHTOWER_ENV}\nMax response bytes: ${env.MAX_RESPONSE_BYTES}\nMax jobs per target: ${env.MAX_JOBS_PER_TARGET}\nGlobal rate/min: ${env.GLOBAL_RATE_LIMIT_PER_MINUTE}\nEvidence retention: ${env.EVIDENCE_RETENTION_DAYS} days\nAudit retention: ${env.AUDIT_RETENTION_DAYS} days\nPassive-only default: ${env.PASSIVE_ONLY_DEFAULT}\nIntrusive testing: ${env.INTRUSIVE_TESTING_ENABLED}\nWordlist module: ${env.WORDLIST_MODULE_ENABLED}\nScope expiry warning: ${env.SCOPE_EXPIRY_WARNING_DAYS} days`);
  },
  team_invite: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /team_invite <org_id> <telegram_id> [role:viewer|analyst|admin]"); return; }
    const [orgId, telegramId, role] = args as [string, string, string | undefined];
    const roleId = await resolveRoleId(env.DB, role ?? "viewer");
    if (!roleId) { await sendMessage(env, ctx.chatId, "⛔ roles table is not seeded (see migrations/0008_seed.sql)."); return; }
    const now = new Date().toISOString();
    // Identity first (users), then authorization (memberships).
    let userId = await findUserIdByTelegram(env.DB, telegramId);
    if (!userId) {
      userId = randomId("user", 12);
      await env.DB
        .prepare(`INSERT INTO users (id, telegram_user_id, display_name, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)`)
        .bind(userId, telegramId, `User ${telegramId}`, now, now)
        .run();
    }
    const invitedBy = await ensureUserId(env.DB, ctx.user);
    try {
      await env.DB
        .prepare(`INSERT INTO memberships (id, organization_id, user_id, role_id, status, invited_by, invited_at, created_at, updated_at)
                  VALUES (?, ?, ?, ?, 'invited', ?, ?, ?, ?)`)
        .bind(randomId("mem", 12), orgId, userId, roleId, invitedBy, now, now, now)
        .run();
    } catch (err) {
      await sendMessage(env, ctx.chatId, `❌ Invite failed: ${String(err)}`);
      return;
    }
    await sendMessage(env, ctx.chatId, `👥 Invited user ${telegramId} as ${role ?? "viewer"}.`);
  },
  team_members: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /team_members <org_id>"); return; }
    const rows = await env.DB
      .prepare(`SELECT u.id, u.telegram_user_id, u.display_name, r.name AS role, m.status
                  FROM memberships m
                  JOIN users u ON u.id = m.user_id
                  JOIN roles r ON r.id = m.role_id
                 WHERE m.organization_id = ?`)
      .bind(args[0])
      .all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["role"]} — ${r["display_name"]} (${r["telegram_user_id"] ?? r["id"]})${r["status"] === "active" ? "" : ` [${r["status"]}]`}`);
    await sendMessage(env, ctx.chatId, lines.length ? `👥 Team:\n\n${lines.join("\n")}` : "No team members yet.");
  },
  audit: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /audit <org_id> [action]"); return; }
    const orgId = args[0]!;
    const action = args[1];
    const where: string[] = ["organization_id = ?"];
    const binds: (string | number)[] = [orgId];
    if (action) { where.push("command = ?"); binds.push(action); }
    const rows = await env.DB.prepare(`SELECT created_at, command, actor_identity, result, result_detail FROM audit_logs WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT 20`).bind(...binds).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["created_at"]} ${r["command"]} ${r["actor_identity"] ?? ""} → ${r["result"]}${r["result_detail"] ? " (" + r["result_detail"] + ")" : ""}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Audit:\n\n${lines.join("\n")}` : "No audit records.");
  },
  stop: async (env, ctx, args) => {
    const es = new EmergencyStopClient(env.DB);
    const scope = (args[0] as "global" | "organization" | "target" | "job") ?? "global";
    const id = args[1];
    const reason = args.slice(2).join(" ") || "manual activation via /stop";
    await es.activate(scope, { id, user_id: ctx.user ? String(ctx.user.id) : null, reason, ttl_seconds: 24 * 3600 });
    // Cancel all in-flight scans for the affected scope
    const stoppedAt = new Date().toISOString();
    const cancelSql = `UPDATE scans SET status = 'cancelled', finished_at = ?, stop_reason = 'emergency_stop', updated_at = ? WHERE status IN ('queued','validating','running')`;
    if (scope === "global") {
      await env.DB.prepare(cancelSql).bind(stoppedAt, stoppedAt).run();
    } else if (scope === "organization" && id) {
      await env.DB.prepare(`${cancelSql} AND organization_id = ?`).bind(stoppedAt, stoppedAt, id).run();
    } else if (scope === "target" && id) {
      await env.DB.prepare(`${cancelSql} AND target_id = ?`).bind(stoppedAt, stoppedAt, id).run();
    }
    await sendMessage(env, ctx.chatId, `🛑 EMERGENCY STOP activated (${scope}${id ? ":" + id : ""}).\nAll in-flight scans for this scope have been cancelled.\nUse /resume ${scope} ${id ?? ""} to lift.`);
  },
  resume: async (env, ctx, args) => {
    const es = new EmergencyStopClient(env.DB);
    const scope = (args[0] as "global" | "organization" | "target" | "job") ?? "global";
    const id = args[1];
    await es.deactivate(scope, id);
    await sendMessage(env, ctx.chatId, `✅ Resumed operations (${scope}${id ? ":" + id : ""}).`);
  },
};
