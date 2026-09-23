// src/db/queries/targets.ts
// Canonical schema (migration-0001):
//   targets: status ('active'|'paused'|'expired'|'retired'), paused_at/paused_by,
//            valid_from/valid_until, max_requests_per_minute, passive_only, low_impact_active,
//            intrusive_enabled, authorization_ref, notes, created_by, created_at, updated_at
//   scopes : id, organization_id, target_id, scope_type, value, display_value, status
//            ('active'|'paused'|'expired'|'removed'), is_primary, is_denylist,
//            include_subdomains, notes, valid_from, valid_until, created_by, created_at, updated_at

import type { Target, ScopeEntry } from "../../types.js";

export async function getTargetById(db: D1Database, targetId: string): Promise<Target | null> {
  const r = await db
    .prepare(`SELECT * FROM targets WHERE id = ?`)
    .bind(targetId)
    .first<Record<string, unknown>>();
  if (!r) return null;
  return rowToTarget(r);
}

export async function listTargets(db: D1Database, orgId: string): Promise<Target[]> {
  const rows = await db
    .prepare(`SELECT * FROM targets WHERE organization_id = ? ORDER BY created_at DESC`)
    .bind(orgId)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToTarget);
}

export async function listScopeEntries(db: D1Database, targetId: string): Promise<ScopeEntry[]> {
  const rows = await db
    .prepare(`SELECT * FROM scopes WHERE target_id = ? AND status != 'removed' ORDER BY is_primary DESC, created_at DESC`)
    .bind(targetId)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToScopeEntry);
}

export async function insertTarget(db: D1Database, t: Target): Promise<void> {
  await db
    .prepare(`INSERT INTO targets (
      id, organization_id, name, passive_only, low_impact_active, intrusive_enabled,
      max_requests_per_minute, authorization_ref, valid_until, status,
      created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`)
    .bind(
      t.id, t.organization_id, t.name, t.passive_only ? 1 : 0,
      t.low_impact_active ? 1 : 0, t.intrusive_enabled ? 1 : 0,
      t.max_request_rate_per_min ?? 60, t.authorization_reference || null,
      t.authorization_expires_at, t.created_by ?? null, t.created_at, t.created_at,
    )
    .run();
}

export async function insertScopeEntry(db: D1Database, e: ScopeEntry): Promise<void> {
  await db
    .prepare(`INSERT INTO scopes (
      id, organization_id, target_id, scope_type, value, display_value, status,
      is_denylist, notes, valid_from, valid_until, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      e.id, e.organization_id, e.target_id, e.type, e.value, e.value,
      e.included === false ? "removed" : "active",
      e.included === false ? 1 : 0,
      e.notes, e.created_at, e.expires_at, e.created_by ?? null, e.created_at, e.created_at,
    )
    .run();
}

export async function pauseTarget(db: D1Database, targetId: string): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE targets SET status = 'paused', paused_at = ?, updated_at = ? WHERE id = ?`)
    .bind(now, now, targetId)
    .run();
}

export async function resumeTarget(db: D1Database, targetId: string): Promise<void> {
  await db
    .prepare(`UPDATE targets SET status = 'active', paused_at = NULL, updated_at = ? WHERE id = ?`)
    .bind(new Date().toISOString(), targetId)
    .run();
}

function rowToTarget(r: Record<string, unknown>): Target {
  return {
    id: String(r["id"]),
    organization_id: String(r["organization_id"]),
    name: String(r["name"]),
    passive_only: !!r["passive_only"],
    low_impact_active: !!r["low_impact_active"],
    intrusive_enabled: !!r["intrusive_enabled"],
    max_request_rate_per_min: Number(r["max_requests_per_minute"] ?? 60),
    max_concurrent_jobs: 1,
    program_rules_url: null,
    // Canonical DB column is `authorization_ref` (migration 0001); the in-memory
    // field keeps its historical name. Reading the wrong name made every target
    // look unauthorized, which failed the scope gate closed and silently
    // reduced every scan to "record everything as out of scope".
    authorization_reference: String(r["authorization_ref"] ?? ""),
    authorization_expires_at: String(r["valid_until"] ?? ""),
    paused: String(r["status"] ?? "active") !== "active",
    created_at: String(r["created_at"]),
    created_by: (r["created_by"] as string | null) ?? null,
  };
}

function rowToScopeEntry(r: Record<string, unknown>): ScopeEntry {
  const active = String(r["status"] ?? "active") === "active";
  const denylist = !!r["is_denylist"];
  return {
    id: String(r["id"]),
    organization_id: String(r["organization_id"] ?? ""),
    target_id: String(r["target_id"]),
    type: r["scope_type"] as ScopeEntry["type"],
    value: String(r["value"]),
    included: active && !denylist,
    notes: (r["notes"] as string | null) ?? null,
    created_at: String(r["created_at"]),
    expires_at: (r["valid_until"] as string | null) ?? null,
    paused: String(r["status"]) === "paused",
    created_by: (r["created_by"] as string | null) ?? null,
  };
}
