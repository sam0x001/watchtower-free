// src/db/queries/audit.ts
import type { AuditEvent } from "../../types.js";

export async function insertAuditLog(db: D1Database, e: AuditEvent): Promise<void> {
  await db
    .prepare(`INSERT INTO audit_logs (
      request_id, timestamp, user_id, telegram_id, organization_id, action,
      target_id, scope_id, job_id, scanner, args_redacted, result, error, ip
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      e.request_id, e.timestamp, e.user_id, e.telegram_id, e.organization_id, e.action,
      e.target_id, e.scope_id, e.job_id, e.scanner, e.args_redacted, e.result, e.error, e.ip,
    )
    .run();
}

export async function listAuditLogs(
  db: D1Database,
  orgId: string,
  opts: { limit?: number; offset?: number; action?: string } = {},
): Promise<AuditEvent[]> {
  const limit = Math.min(Math.max(1, opts.limit ?? 100), 500);
  const offset = Math.max(0, opts.offset ?? 0);
  const where: string[] = ["organization_id = ?"];
  const binds: (string | number)[] = [orgId];
  if (opts.action) { where.push("action = ?"); binds.push(opts.action); }
  const rows = await db
    .prepare(`SELECT * FROM audit_logs WHERE ${where.join(" AND ")} ORDER BY timestamp DESC LIMIT ? OFFSET ?`)
    .bind(...binds, limit, offset)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToEvent);
}

function rowToEvent(r: Record<string, unknown>): AuditEvent {
  return {
    request_id: String(r["request_id"]),
    timestamp: String(r["timestamp"]),
    user_id: (r["user_id"] as string | null) ?? null,
    telegram_id: (r["telegram_id"] as string | null) ?? null,
    organization_id: (r["organization_id"] as string | null) ?? null,
    action: String(r["action"]),
    target_id: (r["target_id"] as string | null) ?? null,
    scope_id: (r["scope_id"] as string | null) ?? null,
    job_id: (r["job_id"] as string | null) ?? null,
    scanner: (r["scanner"] as string | null) ?? null,
    args_redacted: String(r["args_redacted"] ?? "{}"),
    result: r["result"] as AuditEvent["result"],
    error: (r["error"] as string | null) ?? null,
    ip: (r["ip"] as string | null) ?? null,
  };
}
