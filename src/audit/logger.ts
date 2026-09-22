// src/audit/logger.ts
// Append-only audit logger. Every command, scan, finding mutation, evidence
// access, and integration change is recorded here.
//
// Secret values are scrubbed BEFORE they reach this logger by the redaction
// module. As defense-in-depth, the logger additionally rejects fields whose
// names suggest secrets.

import type { AuditActorKind, AuditEvent } from "../types.js";
import type { Env } from "../env.js";
import { randomId } from "../crypto/hash.js";
import { containsLikelySecret } from "../security/redaction.js";

const SENSITIVE_KEYS = new Set([
  "password", "passwd", "pwd", "secret", "api_key", "apikey", "token",
  "authorization", "auth", "cookie", "session", "private_key", "privateKey",
  "bearer", "access_token", "refresh_token", "client_secret",
]);

function scrubArgs(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    const lower = k.toLowerCase();
    if (SENSITIVE_KEYS.has(lower) || lower.includes("secret") || lower.includes("token")) {
      out[k] = "<redacted>";
      continue;
    }
    if (typeof v === "string") {
      if (containsLikelySecret(v)) out[k] = "<redacted>";
      else out[k] = v.length > 1000 ? v.slice(0, 1000) + "...(truncated)" : v;
    } else {
      try {
        out[k] = JSON.parse(JSON.stringify(v));
      } catch {
        out[k] = "<unserializable>";
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Canonical audit_logs mapping
//
// The table is declared in migrations/0001_initial.sql. Its NOT NULL columns
// (actor_kind, command, result, created_at) must always be populated, and
// `result` is constrained to ('success','denied','error','pending_approval').
// The helpers below translate the friendlier in-memory AuditEvent shape onto
// that schema so every writer lands in the same columns.
// ---------------------------------------------------------------------------

const AUDIT_ACTOR_KINDS: readonly AuditActorKind[] = ["telegram", "api", "system", "runner", "webhook"];

/** Parse `args_redacted` (JSON text) into an object. Never throws. */
function parseArgs(raw: string | null | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return { value: parsed };
  } catch {
    return { raw };
  }
}

export function isAuditActorKind(value: unknown): value is AuditActorKind {
  return typeof value === "string" && (AUDIT_ACTOR_KINDS as readonly string[]).includes(value);
}

/**
 * `actor_kind` is NOT NULL: an explicit value wins, otherwise infer it from the
 * action prefix, then from the actor ids, defaulting to "system".
 */
export function resolveActorKind(event: AuditEvent): AuditActorKind {
  if (isAuditActorKind(event.actor_kind)) return event.actor_kind;
  const action = event.action ?? "";
  if (action.startsWith("telegram.")) return "telegram";
  if (action.startsWith("api.")) return "api";
  if (action.startsWith("runner.")) return "runner";
  if (action.startsWith("webhook.")) return "webhook";
  if (event.telegram_id) return "telegram";
  return "system";
}

/**
 * Map the in-memory result vocabulary onto the audit_logs CHECK constraint:
 * "failure" -> "error", "blocked" -> "denied".
 */
export function resolveAuditResult(result: AuditEvent["result"]): string {
  switch (result) {
    case "success": return "success";
    case "denied": return "denied";
    case "blocked": return "denied";
    case "pending_approval": return "pending_approval";
    default: return "error";
  }
}

/**
 * Canonical audit_logs column order. The INSERT statement and the bound row are
 * both derived from this list, so they cannot drift apart.
 */
export const AUDIT_INSERT_COLUMNS = [
  "id", "organization_id", "actor_user_id", "actor_kind", "actor_identity", "command",
  "target_id", "scope_id", "job_id", "runner_id", "scanner", "arguments_redacted",
  "result", "result_detail", "request_metadata", "correlation_id", "created_at",
] as const;

export const AUDIT_INSERT_SQL =
  `INSERT INTO audit_logs (${AUDIT_INSERT_COLUMNS.join(", ")}) ` +
  `VALUES (${AUDIT_INSERT_COLUMNS.map(() => "?").join(", ")})`;

/**
 * Build the bind array matching AUDIT_INSERT_SQL. The ip/telegram/user context
 * is stored as JSON in `request_metadata` (the table has no `ip` column).
 */
export function buildAuditRow(event: AuditEvent): (string | null)[] {
  return [
    randomId("audit", 12),                                   // id
    event.organization_id,                                   // organization_id
    event.user_id,                                           // actor_user_id
    resolveActorKind(event),                                 // actor_kind      (NOT NULL)
    event.actor_identity ?? event.telegram_id ?? event.user_id ?? null, // actor_identity
    event.action || "unknown.action",                        // command         (NOT NULL)
    event.target_id,                                         // target_id
    event.scope_id,                                          // scope_id
    event.job_id,                                            // job_id
    event.runner_id ?? null,                                 // runner_id
    event.scanner,                                           // scanner
    event.args_redacted ?? "{}",                             // arguments_redacted
    resolveAuditResult(event.result),                        // result          (NOT NULL)
    event.error,                                             // result_detail
    JSON.stringify({                                         // request_metadata
      ip: event.ip ?? null,
      user_id: event.user_id ?? null,
      telegram_id: event.telegram_id ?? null,
    }),
    event.request_id,                                        // correlation_id
    event.timestamp || new Date().toISOString(),             // created_at      (NOT NULL)
  ];
}

export function newRequestId(): string {
  return randomId("req", 12);
}

export interface AuditLogger {
  log(event: AuditEvent): Promise<void>;
}

export class D1AuditLogger implements AuditLogger {
  constructor(private db: D1Database) {}

  async log(event: AuditEvent): Promise<void> {
    const scrubbed: AuditEvent = {
      ...event,
      args_redacted: JSON.stringify(scrubArgs(parseArgs(event.args_redacted))),
    };
    // Never log if the args still contain a likely secret
    if (containsLikelySecret(scrubbed.args_redacted)) {
      scrubbed.args_redacted = "{}";
      scrubbed.error = (scrubbed.error ?? "") + "; args scrubbed due to suspected secret";
    }
    await this.db.prepare(AUDIT_INSERT_SQL).bind(...buildAuditRow(scrubbed)).run();
  }
}

export interface ConsoleLogger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export function makeConsoleLogger(level: "debug" | "info" | "warn" | "error"): ConsoleLogger {
  const rank = { debug: 0, info: 1, warn: 2, error: 3 };
  return {
    debug(m, f) { if (rank[level] <= 0) console.log(JSON.stringify({ level: "debug", msg: m, ...f })); },
    info(m, f) { if (rank[level] <= 1) console.log(JSON.stringify({ level: "info", msg: m, ...f })); },
    warn(m, f) { if (rank[level] <= 2) console.warn(JSON.stringify({ level: "warn", msg: m, ...f })); },
    error(m, f) { if (rank[level] <= 3) console.error(JSON.stringify({ level: "error", msg: m, ...f })); },
  };
}

export const log = makeConsoleLogger("info");
