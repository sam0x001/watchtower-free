// src/db/queries/audit.ts
import type { AuditActorKind, AuditEvent } from "../../types.js";
import { D1AuditLogger, isAuditActorKind } from "../../audit/logger.js";

/** Canonical audit_logs columns (see migrations/0001_initial.sql). */
const AUDIT_READ_COLUMNS =
  "id, organization_id, actor_user_id, actor_kind, actor_identity, command, " +
  "target_id, scope_id, job_id, runner_id, scanner, arguments_redacted, " +
  "result, result_detail, request_metadata, correlation_id, created_at";

/**
 * Kept for callers that only hold a D1 binding. It delegates to D1AuditLogger so
 * every audit write goes through the same canonical mapping.
 */
export async function insertAuditLog(db: D1Database, e: AuditEvent): Promise<void> {
  await new D1AuditLogger(db).log(e);
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
  // The API keeps the query param name `action`; the column is `command`.
  if (opts.action) { where.push("command = ?"); binds.push(opts.action); }
  const rows = await db
    .prepare(`SELECT ${AUDIT_READ_COLUMNS} FROM audit_logs WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .bind(...binds, limit, offset)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToEvent);
}

function rowToEvent(r: Record<string, unknown>): AuditEvent {
  const meta = parseRequestMetadata(r["request_metadata"]);
  const actorKind = r["actor_kind"];
  return {
    request_id: String(r["correlation_id"] ?? ""),
    timestamp: String(r["created_at"] ?? ""),
    user_id: (r["actor_user_id"] as string | null) ?? (meta["user_id"] as string | null) ?? null,
    telegram_id: (r["actor_identity"] as string | null) ?? (meta["telegram_id"] as string | null) ?? null,
    organization_id: (r["organization_id"] as string | null) ?? null,
    action: String(r["command"] ?? ""),
    target_id: (r["target_id"] as string | null) ?? null,
    scope_id: (r["scope_id"] as string | null) ?? null,
    job_id: (r["job_id"] as string | null) ?? null,
    scanner: (r["scanner"] as string | null) ?? null,
    args_redacted: String(r["arguments_redacted"] ?? "{}"),
    result: toEventResult(r["result"]),
    error: (r["result_detail"] as string | null) ?? null,
    ip: (meta["ip"] as string | null) ?? null,
    actor_kind: isAuditActorKind(actorKind) ? (actorKind as AuditActorKind) : undefined,
  };
}

/** audit_logs.result -> in-memory result vocabulary. */
function toEventResult(result: unknown): AuditEvent["result"] {
  switch (result) {
    case "success": return "success";
    case "denied": return "denied";
    case "pending_approval": return "pending_approval";
    default: return "failure";
  }
}

function parseRequestMetadata(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "string" || !raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
