// src/db/queries/targets.ts

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
    .prepare(`SELECT * FROM scope_entries WHERE target_id = ? ORDER BY included DESC, created_at DESC`)
    .bind(targetId)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToScopeEntry);
}

export async function insertTarget(db: D1Database, t: Target): Promise<void> {
  await db
    .prepare(`INSERT INTO targets (
      id, organization_id, name, passive_only, low_impact_active, intrusive_enabled,
      max_request_rate_per_min, max_concurrent_jobs, program_rules_url,
      authorization_reference, authorization_expires_at, paused, scan_profile_json,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      t.id, t.organization_id, t.name, t.passive_only ? 1 : 0,
      t.low_impact_active ? 1 : 0, t.intrusive_enabled ? 1 : 0,
      t.max_request_rate_per_min, t.max_concurrent_jobs, t.program_rules_url,
      t.authorization_reference, t.authorization_expires_at, t.paused ? 1 : 0,
      JSON.stringify({}), t.created_at, t.created_at,
    )
    .run();
}

export async function insertScopeEntry(db: D1Database, e: ScopeEntry): Promise<void> {
  await db
    .prepare(`INSERT INTO scope_entries (
      id, target_id, type, value, included, notes, created_at, expires_at, paused
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      e.id, e.target_id, e.type, e.value, e.included ? 1 : 0, e.notes,
      e.created_at, e.expires_at, e.paused ? 1 : 0,
    )
    .run();
}

export async function pauseTarget(db: D1Database, targetId: string): Promise<void> {
  await db
    .prepare(`UPDATE targets SET paused = 1, updated_at = ? WHERE id = ?`)
    .bind(new Date().toISOString(), targetId)
    .run();
}

export async function resumeTarget(db: D1Database, targetId: string): Promise<void> {
  await db
    .prepare(`UPDATE targets SET paused = 0, updated_at = ? WHERE id = ?`)
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
    max_request_rate_per_min: Number(r["max_request_rate_per_min"]),
    max_concurrent_jobs: Number(r["max_concurrent_jobs"]),
    program_rules_url: (r["program_rules_url"] as string | null) ?? null,
    authorization_reference: String(r["authorization_reference"] ?? ""),
    authorization_expires_at: String(r["authorization_expires_at"]),
    paused: !!r["paused"],
    created_at: String(r["created_at"]),
  };
}

function rowToScopeEntry(r: Record<string, unknown>): ScopeEntry {
  return {
    id: String(r["id"]),
    target_id: String(r["target_id"]),
    type: r["type"] as ScopeEntry["type"],
    value: String(r["value"]),
    included: !!r["included"],
    notes: (r["notes"] as string | null) ?? null,
    created_at: String(r["created_at"]),
    expires_at: (r["expires_at"] as string | null) ?? null,
    paused: !!r["paused"],
  };
}
