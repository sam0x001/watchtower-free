// src/audit/logger.ts
// Append-only audit logger. Every command, scan, finding mutation, evidence
// access, and integration change is recorded here.
//
// Secret values are scrubbed BEFORE they reach this logger by the redaction
// module. As defense-in-depth, the logger additionally rejects fields whose
// names suggest secrets.

import type { AuditEvent } from "../types.js";
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
      args_redacted: JSON.stringify(scrubArgs(JSON.parse(event.args_redacted || "{}"))),
    };
    // Never log if the args still contain a likely secret
    if (containsLikelySecret(scrubbed.args_redacted)) {
      scrubbed.args_redacted = "{}";
      scrubbed.error = (scrubbed.error ?? "") + "; args scrubbed due to suspected secret";
    }
    await this.db
      .prepare(
        `INSERT INTO audit_logs (
          request_id, timestamp, user_id, telegram_id, organization_id, action,
          target_id, scope_id, job_id, scanner, args_redacted, result, error, ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        scrubbed.request_id,
        scrubbed.timestamp,
        scrubbed.user_id,
        scrubbed.telegram_id,
        scrubbed.organization_id,
        scrubbed.action,
        scrubbed.target_id,
        scrubbed.scope_id,
        scrubbed.job_id,
        scrubbed.scanner,
        scrubbed.args_redacted,
        scrubbed.result,
        scrubbed.error,
        scrubbed.ip,
      )
      .run();
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
