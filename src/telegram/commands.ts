// src/telegram/commands.ts
// Command router for Telegram. Implements all 44 commands listed in the spec.

import type { Env } from "../env.js";
import type { ConsoleLogger, D1AuditLogger } from "../audit/logger.js";
import { sendMessage } from "./webhook.js";
import { messages } from "./messages.js";
import { EmergencyStopClient } from "../db/emergency-stop.js";
import { enqueueJob, cancelJob } from "../db/job-queue.js";
import { randomId } from "../crypto/hash.js";

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
  const handler = handlers[command] ?? handlers["help"];
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
    await ctx.audit.log({
      timestamp: new Date().toISOString(),
      user_id: null,
      telegram_id: ctx.user ? String(ctx.user.id) : null,
      organization_id: null,
      action: "telegram.authorize",
      target_id: null,
      scope_id: null,
      job_id: null,
      scanner: null,
      args_redacted: JSON.stringify({ target_name: targetName, reference }),
      result: "success",
      error: null,
      ip: null,
      request_id: ctx.requestId,
    });
    await sendMessage(env, ctx.chatId, `✅ Authorization recorded for ${targetName}.\nReference: ${reference}\n\nYou may now use /scope_add to define the in-scope assets.`);
  },
  scope_add: async (env, ctx, args) => {
    if (args.length < 2) {
      await sendMessage(env, ctx.chatId, "Usage: /scope_add <target_id> <type:domain|wildcard_domain|ip|cidr|url|api> <value> [--exclude]\nExample: /scope_add TGT_abc domain example.com");
      return;
    }
    const [targetId, type, ...rest] = args;
    const exclude = rest.includes("--exclude");
    const value = rest.filter((a) => a !== "--exclude").join(" ");
    const id = randomId("scope", 12);
    await env.DB
      .prepare(`INSERT INTO scope_entries (id, target_id, type, value, included, notes, created_at, expires_at, paused) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, targetId, type, value, exclude ? 0 : 1, null, new Date().toISOString(), null, 0)
      .run();
    await sendMessage(env, ctx.chatId, `✅ Scope entry added: ${type} ${value} (${exclude ? "denylist" : "allowlist"})\nID: ${id}`);
  },
  scope_list: async (env, ctx, args) => {
    const targetId = args[0];
    if (!targetId) { await sendMessage(env, ctx.chatId, "Usage: /scope_list <target_id>"); return; }
    const rows = await env.DB
      .prepare(`SELECT * FROM scope_entries WHERE target_id = ? ORDER BY included DESC, created_at DESC`)
      .bind(targetId)
      .all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["included"] ? "✅" : "🚫"} [${r["type"]}] ${r["value"]}  ${r["paused"] ? "(paused)" : ""}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Scope for ${targetId}:\n\n${lines.join("\n")}` : "No scope entries yet.");
  },
  scope_update: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /scope_update <scope_id> <new_value>"); return; }
    const [scopeId, value] = args;
    await env.DB.prepare(`UPDATE scope_entries SET value = ? WHERE id = ?`).bind(value, scopeId).run();
    await sendMessage(env, ctx.chatId, `✅ Scope ${scopeId} updated to ${value}`);
  },
  scope_remove: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scope_remove <scope_id>"); return; }
    await env.DB.prepare(`DELETE FROM scope_entries WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, `🗑 Removed scope entry ${args[0]}`);
  },
  scope_pause: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE scope_entries SET paused = 1 WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, `⏸ Paused scope ${args[0]}`);
  },
  scope_resume: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE scope_entries SET paused = 0 WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, `▶️ Resumed scope ${args[0]}`);
  },
  scope_expire: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE scope_entries SET expires_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `⌛ Marked scope ${args[0]} as expired`);
  },
  target_add: async (env, ctx, args) => {
    if (args.length < 3) {
      await sendMessage(env, ctx.chatId, "Usage: /target_add <org_id> <name> <authorization_expires_at:YYYY-MM-DD> [program_rules_url]");
      return;
    }
    const [orgId, name, expiresAt, rulesUrl] = args;
    const id = randomId("tgt", 12);
    await env.DB
      .prepare(`INSERT INTO targets (id, organization_id, name, passive_only, low_impact_active, intrusive_enabled, max_request_rate_per_min, max_concurrent_jobs, program_rules_url, authorization_reference, authorization_expires_at, paused, scan_profile_json, created_at, updated_at) VALUES (?, ?, ?, 1, 0, 0, 60, 3, ?, ?, ?, 0, '{}', ?, ?)`)
      .bind(id, orgId, name, rulesUrl ?? null, `telegram:${ctx.user?.id ?? "unknown"}`, expiresAt, new Date().toISOString(), new Date().toISOString())
      .run();
    await sendMessage(env, ctx.chatId, `✅ Target created.\nID: ${id}\nName: ${name}\nExpires: ${expiresAt}`);
  },
  target_list: async (env, ctx, args) => {
    const orgId = args[0];
    if (!orgId) { await sendMessage(env, ctx.chatId, "Usage: /target_list <org_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, name, paused, authorization_expires_at FROM targets WHERE organization_id = ?`).bind(orgId).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["paused"] ? "⏸" : "🟢"} ${r["id"]} — ${r["name"]} (expires ${r["authorization_expires_at"]})`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Targets:\n\n${lines.join("\n")}` : "No targets yet.");
  },
  target_details: async (env, ctx, args) => {
    const r = await env.DB.prepare(`SELECT * FROM targets WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Target not found"); return; }
    await sendMessage(env, ctx.chatId, `🎯 ${r["name"]}\nID: ${r["id"]}\nOrg: ${r["organization_id"]}\nPassive: ${r["passive_only"]}\nLow-impact active: ${r["low_impact_active"]}\nMax r/min: ${r["max_request_rate_per_min"]}\nMax concurrent: ${r["max_concurrent_jobs"]}\nExpires: ${r["authorization_expires_at"]}\nPaused: ${r["paused"]}`);
  },
  target_pause: async (env, ctx, args) => { await env.DB.prepare(`UPDATE targets SET paused = 1 WHERE id = ?`).bind(args[0]).run(); await sendMessage(env, ctx.chatId, "⏸ Target paused"); },
  target_resume: async (env, ctx, args) => { await env.DB.prepare(`UPDATE targets SET paused = 0 WHERE id = ?`).bind(args[0]).run(); await sendMessage(env, ctx.chatId, "▶️ Target resumed"); },
  scan_passive: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_passive <target_id>"); return; }
    const targetId = args[0]!;
    // Check emergency stop first
    const es = new EmergencyStopClient(env.DB);
    if (await es.isBlocked("target", targetId)) { await sendMessage(env, ctx.chatId, "⛔ Emergency stop is active for this target. Use /resume after resolving."); return; }
    const jobId = randomId("scan", 12);
    await env.DB.prepare(`INSERT INTO scans (id, target_id, organization_id, profile, triggered_by, triggered_by_user_id, status, created_at) VALUES (?, ?, (SELECT organization_id FROM targets WHERE id = ?), 'passive-only', 'telegram', NULL, 'queued', ?)`)
      .bind(jobId, targetId, targetId, new Date().toISOString()).run();
    await enqueueJob(env.DB, "scan", {
      job_id: jobId, target_id: targetId,
      organization_id: "", // filled by scan-runner
      profile: "passive-only", triggered_by: "telegram", triggered_by_user_id: null,
      attempt: 0, enqueued_at: new Date().toISOString(),
    }, { dedup_key: `scan:${targetId}:${new Date().toISOString().slice(0, 16)}` });
    await sendMessage(env, ctx.chatId, `🟢 Passive scan queued.\nScan ID: ${jobId}\nRuns within ~5 minutes (next cron tick). Use /scan_status ${jobId} to track.`);
  },
  scan_active: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_active <target_id> [confirm]\n⚠️ Requires explicit human approval. Add 'confirm' as second arg to proceed."); return; }
    if (args[1] !== "confirm") { await sendMessage(env, ctx.chatId, "⚠️ Active scans require human approval.\nRe-run with: /scan_active <target_id> confirm"); return; }
    const targetId = args[0]!;
    await env.DB.prepare(`UPDATE targets SET low_impact_active = 1 WHERE id = ?`).bind(targetId).run();
    await sendMessage(env, ctx.chatId, "⚠️ Low-impact active scans enabled. Passive baseline will run first; intrusive checks remain blocked unless separately approved.");
  },
  scan_status: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_status <scan_id>"); return; }
    const r = await env.DB.prepare(`SELECT * FROM scans WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Scan not found"); return; }
    await sendMessage(env, ctx.chatId, `Scan ${r["id"]}\nStatus: ${r["status"]}\nProfile: ${r["profile"]}\nCreated: ${r["created_at"]}\nStarted: ${r["started_at"]}\nCompleted: ${r["completed_at"]}\nError: ${r["error"] ?? "none"}`);
  },
  scan_cancel: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /scan_cancel <scan_id>"); return; }
    const jobId = args[0]!;
    const es = new EmergencyStopClient(env.DB);
    await es.cancelJob(jobId, ctx.user ? String(ctx.user.id) : null, "telegram.cancel");
    await cancelJob(env.DB, jobId, "telegram.cancel");
    await env.DB.prepare(`UPDATE scans SET status = 'cancelled', completed_at = ? WHERE id = ?`).bind(new Date().toISOString(), jobId).run();
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
    await env.DB.prepare(`UPDATE findings SET verification_state = 'verified', status = 'in_review', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `✅ Finding ${args[0]} marked as verified.`);
  },
  finding_reject: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /finding_reject <finding_id>"); return; }
    await env.DB.prepare(`UPDATE findings SET verification_state = 'false_positive', status = 'closed', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `🚫 Finding ${args[0]} rejected as false positive.`);
  },
  finding_assign: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /finding_assign <finding_id> <user_id>"); return; }
    await env.DB.prepare(`UPDATE findings SET assigned_user_id = ?, status = 'assigned', updated_at = ? WHERE id = ?`).bind(args[1], new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `📌 Finding ${args[0]} assigned to ${args[1]}.`);
  },
  finding_close: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE findings SET status = 'closed', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `✅ Finding ${args[0]} closed.`);
  },
  finding_reopen: async (env, ctx, args) => {
    await env.DB.prepare(`UPDATE findings SET status = 'reopened', verification_state = 'detected', updated_at = ? WHERE id = ?`).bind(new Date().toISOString(), args[0]).run();
    await sendMessage(env, ctx.chatId, `↩️ Finding ${args[0]} reopened.`);
  },
  report_create: async (env, ctx, args) => {
    if (args.length < 2) { await sendMessage(env, ctx.chatId, "Usage: /report_create <target_id> <format:markdown|json|hackerone|bugcrowd|internal|executive>"); return; }
    const [targetId, format] = args as [string, string];
    const id = randomId("rep", 12);
    const target = await env.DB.prepare(`SELECT organization_id FROM targets WHERE id = ?`).bind(targetId).first<{ organization_id: string }>();
    if (!target) { await sendMessage(env, ctx.chatId, "Target not found"); return; }
    await env.DB.prepare(`INSERT INTO reports (id, organization_id, target_id, format, scope_json, findings_count, created_at) VALUES (?, ?, ?, ?, '{}', 0, ?)`)
      .bind(id, target.organization_id, targetId, format, new Date().toISOString()).run();
    await enqueueJob(env.DB, "notification", {
      organization_id: target.organization_id, target_id: targetId, channel: "telegram", severity: "informational", payload: { report_id: id, format }, dedup_key: `report:${id}`, attempt: 0,
    }, { dedup_key: `report:${id}` });
    await sendMessage(env, ctx.chatId, `📄 Report ${id} queued for generation (${format}).`);
  },
  report_export: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /report_export <report_id>"); return; }
    const r = await env.DB.prepare(`SELECT * FROM reports WHERE id = ?`).bind(args[0]).first<Record<string, unknown>>();
    if (!r) { await sendMessage(env, ctx.chatId, "Report not found"); return; }
    await sendMessage(env, ctx.chatId, `📄 Report ${r["id"]}\nFormat: ${r["format"]}\nCreated: ${r["created_at"]}\nFindings: ${r["findings_count"]}\nR2 key: ${r["r2_key"] ?? "pending"}`);
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
    await env.DB.prepare(`UPDATE targets SET scan_profile_json = json_set(scan_profile_json, '$.alerts_enabled', 1) WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, "🔔 Alerts enabled.");
  },
  alerts_disable: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /alerts_disable <target_id>"); return; }
    await env.DB.prepare(`UPDATE targets SET scan_profile_json = json_set(scan_profile_json, '$.alerts_enabled', 0) WHERE id = ?`).bind(args[0]).run();
    await sendMessage(env, ctx.chatId, "🔕 Alerts disabled.");
  },
  schedule_add: async (env, ctx, args) => {
    if (args.length < 3) { await sendMessage(env, ctx.chatId, "Usage: /schedule_add <target_id> <cron_expr> <profile>"); return; }
    const [targetId, cronExpr, profile] = args as [string, string, string];
    const id = randomId("sch", 12);
    await env.DB.prepare(`INSERT INTO schedules (id, target_id, cron_expr, profile, enabled, jitter_ms, created_at) VALUES (?, ?, ?, ?, 1, 5000, ?)`)
      .bind(id, targetId, cronExpr, profile, new Date().toISOString()).run();
    await sendMessage(env, ctx.chatId, `📅 Schedule added.\nID: ${id}\nCron: ${cronExpr}\nProfile: ${profile}`);
  },
  schedule_list: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /schedule_list <target_id>"); return; }
    const rows = await env.DB.prepare(`SELECT id, cron_expr, profile, enabled, last_run_at, next_run_at FROM schedules WHERE target_id = ?`).bind(args[0]).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["enabled"] ? "🟢" : "⏸"} ${r["id"]} — ${r["cron_expr"]} (${r["profile"]}) next=${r["next_run_at"] ?? "n/a"}`);
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
    const id = randomId("int", 12);
    await env.DB.prepare(`INSERT INTO integrations (id, organization_id, type, config_json, encrypted_secret, enabled, created_at) VALUES (?, ?, ?, ?, NULL, 1, ?)`)
      .bind(id, orgId, type, config, new Date().toISOString()).run();
    await sendMessage(env, ctx.chatId, `🔌 Integration added (${type}). ID: ${id}`);
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
    const r = role ?? "viewer";
    const id = randomId("user", 12);
    await env.DB.prepare(`INSERT INTO users (id, telegram_id, display_name, organization_id, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(id, telegramId, `User ${telegramId}`, orgId, r, new Date().toISOString()).run();
    await env.DB.prepare(`INSERT INTO memberships (user_id, organization_id, role, created_at) VALUES (?, ?, ?, ?)`)
      .bind(id, orgId, r, new Date().toISOString()).run();
    await sendMessage(env, ctx.chatId, `👥 Invited user ${telegramId} as ${r}.`);
  },
  team_members: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /team_members <org_id>"); return; }
    const rows = await env.DB.prepare(`SELECT u.id, u.telegram_id, u.display_name, u.role FROM users u WHERE u.organization_id = ?`).bind(args[0]).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["role"]} — ${r["display_name"]} (${r["telegram_id"] ?? r["id"]})`);
    await sendMessage(env, ctx.chatId, lines.length ? `👥 Team:\n\n${lines.join("\n")}` : "No team members yet.");
  },
  audit: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /audit <org_id> [action]"); return; }
    const orgId = args[0]!;
    const action = args[1];
    const where: string[] = ["organization_id = ?"];
    const binds: (string | number)[] = [orgId];
    if (action) { where.push("action = ?"); binds.push(action); }
    const rows = await env.DB.prepare(`SELECT timestamp, action, telegram_id, result, error FROM audit_logs WHERE ${where.join(" AND ")} ORDER BY timestamp DESC LIMIT 20`).bind(...binds).all<Record<string, unknown>>();
    const lines = (rows.results ?? []).map((r) => `${r["timestamp"]} ${r["action"]} ${r["telegram_id"] ?? ""} → ${r["result"]}${r["error"] ? " (" + r["error"] + ")" : ""}`);
    await sendMessage(env, ctx.chatId, lines.length ? `📋 Audit:\n\n${lines.join("\n")}` : "No audit records.");
  },
  stop: async (env, ctx, args) => {
    const es = new EmergencyStopClient(env.DB);
    const scope = (args[0] as "global" | "organization" | "target" | "job") ?? "global";
    const id = args[1];
    const reason = args.slice(2).join(" ") || "manual activation via /stop";
    await es.activate(scope, { id, user_id: ctx.user ? String(ctx.user.id) : null, reason, ttl_seconds: 24 * 3600 });
    // Cancel all in-flight scans for the affected scope
    if (scope === "global") {
      await env.DB.prepare(`UPDATE scans SET status = 'cancelled', completed_at = ? WHERE status IN ('queued','running')`).bind(new Date().toISOString()).run();
    } else if (scope === "organization" && id) {
      await env.DB.prepare(`UPDATE scans SET status = 'cancelled', completed_at = ? WHERE organization_id = ? AND status IN ('queued','running')`).bind(new Date().toISOString(), id).run();
    } else if (scope === "target" && id) {
      await env.DB.prepare(`UPDATE scans SET status = 'cancelled', completed_at = ? WHERE target_id = ? AND status IN ('queued','running')`).bind(new Date().toISOString(), id).run();
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
