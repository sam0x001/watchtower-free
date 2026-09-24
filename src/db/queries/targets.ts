// src/db/queries/targets.ts
// Target + scope + allowed-user persistence (migrations/0001_core.sql).

import type { Target, TargetGroup, ScopeEntry, ScopeType } from "../../types.js";
import { randomId } from "../../crypto/hash.js";

export async function getTargetById(db: D1Database, targetId: string): Promise<Target | null> {
  const r = await db
    .prepare(`SELECT * FROM targets WHERE id = ?`)
    .bind(targetId)
    .first<Record<string, unknown>>();
  if (!r) return null;
  return rowToTarget(r);
}

/** Resolve a target by name (root domain, e.g. example.com) or by id. */
export async function getTargetByNameOrId(db: D1Database, nameOrId: string): Promise<Target | null> {
  const byId = await getTargetById(db, nameOrId);
  if (byId) return byId;
  const r = await db
    .prepare(`SELECT * FROM targets WHERE name = ?`)
    .bind(nameOrId.toLowerCase())
    .first<Record<string, unknown>>();
  if (!r) return null;
  return rowToTarget(r);
}

export async function listTargets(db: D1Database): Promise<Target[]> {
  const rows = await db
    .prepare(`SELECT * FROM targets ORDER BY created_at DESC`)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToTarget);
}

export async function listScopeEntries(db: D1Database, targetId: string): Promise<ScopeEntry[]> {
  const rows = await db
    .prepare(`SELECT * FROM scopes WHERE target_id = ? AND status != 'removed' ORDER BY is_denylist ASC, created_at ASC`)
    .bind(targetId)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToScopeEntry);
}

/** Create a target plus its root allowlist scope entry in one go. */
export async function createTarget(
  db: D1Database,
  name: string,
  telegramUserId: string | null,
  groupId: string | null = null,
): Promise<Target> {
  const id = randomId("tgt", 12);
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO targets (id, name, organization_id, group_id, status, created_by, created_at, updated_at)
       VALUES (?, ?, 'default', ?, 'active', ?, ?, ?)`,
    )
    .bind(id, name, groupId, telegramUserId, now, now)
    .run();
  await insertScopeEntry(db, id, "domain", name, false, telegramUserId);
  const created = await getTargetById(db, id);
  return created!;
}

export async function insertScopeEntry(
  db: D1Database,
  targetId: string,
  type: ScopeType,
  value: string,
  isDenylist: boolean,
  createdBy: string | null,
): Promise<string> {
  const id = randomId("scope", 12);
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO scopes (id, target_id, scope_type, value, display_value, is_denylist, status, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
    )
    .bind(id, targetId, type, value, value, isDenylist ? 1 : 0, createdBy, now, now)
    .run();
  return id;
}

export async function removeScopeEntry(db: D1Database, targetId: string, value: string): Promise<boolean> {
  const result = await db
    .prepare(`UPDATE scopes SET status = 'removed', updated_at = ? WHERE target_id = ? AND value = ? AND status = 'active'`)
    .bind(new Date().toISOString(), targetId, value)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

export async function pauseTarget(db: D1Database, targetId: string): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE targets SET status = 'paused', paused_at = ?, updated_at = ? WHERE id = ?`)
    .bind(now, now, targetId)
    .run();
}

export async function resumeTarget(db: D1Database, targetId: string): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE targets SET status = 'active', paused_at = NULL, updated_at = ? WHERE id = ?`)
    .bind(now, targetId)
    .run();
}

export async function deleteTarget(db: D1Database, targetId: string): Promise<void> {
  // Cascades to scopes/assets/findings via FK ON DELETE CASCADE.
  await db.prepare(`DELETE FROM targets WHERE id = ?`).bind(targetId).run();
}

// ---------------------------------------------------------------------------
// Target groups (categories) — migrations/0006_target_groups.sql
// ---------------------------------------------------------------------------

/** Create a named bucket of domains, e.g. /target_add shop. */
export async function createTargetGroup(
  db: D1Database,
  name: string,
  telegramUserId: string | null,
): Promise<TargetGroup> {
  const id = randomId("grp", 12);
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO target_groups (id, name, organization_id, created_by, created_at, updated_at)
       VALUES (?, ?, 'default', ?, ?, ?)`,
    )
    .bind(id, name, telegramUserId, now, now)
    .run();
  return { id, name, organization_id: "default", created_at: now, created_by: telegramUserId };
}

export async function getTargetGroupById(db: D1Database, groupId: string): Promise<TargetGroup | null> {
  const r = await db
    .prepare(`SELECT * FROM target_groups WHERE id = ?`)
    .bind(groupId)
    .first<Record<string, unknown>>();
  return r ? rowToTargetGroup(r) : null;
}

/** Resolve a group by its human name (case-insensitive) or by id. */
export async function getTargetGroupByNameOrId(
  db: D1Database,
  nameOrId: string,
): Promise<TargetGroup | null> {
  const byId = await getTargetGroupById(db, nameOrId);
  if (byId) return byId;
  const r = await db
    .prepare(`SELECT * FROM target_groups WHERE name = ? COLLATE NOCASE`)
    .bind(nameOrId)
    .first<Record<string, unknown>>();
  return r ? rowToTargetGroup(r) : null;
}

export async function listTargetGroups(db: D1Database): Promise<TargetGroup[]> {
  const rows = await db
    .prepare(`SELECT * FROM target_groups ORDER BY created_at DESC`)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToTargetGroup);
}

/** All targets belonging to a group, oldest first (stable display order). */
export async function listTargetsByGroup(db: D1Database, groupId: string): Promise<Target[]> {
  const rows = await db
    .prepare(`SELECT * FROM targets WHERE group_id = ? ORDER BY created_at ASC`)
    .bind(groupId)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToTarget);
}

/** Move a target into a group (or detach it with null). */
export async function setTargetGroup(
  db: D1Database,
  targetId: string,
  groupId: string | null,
): Promise<void> {
  await db
    .prepare(`UPDATE targets SET group_id = ?, updated_at = ? WHERE id = ?`)
    .bind(groupId, new Date().toISOString(), targetId)
    .run();
}

/** Delete a group. Members are detached (FK ON DELETE SET NULL), not deleted. */
export async function deleteTargetGroup(db: D1Database, groupId: string): Promise<void> {
  await db.prepare(`DELETE FROM target_groups WHERE id = ?`).bind(groupId).run();
}

// ---------------------------------------------------------------------------
// Allowed Telegram users (bot access control)
// ---------------------------------------------------------------------------

export async function listAllowedUsers(db: D1Database): Promise<string[]> {
  const rows = await db.prepare(`SELECT telegram_id FROM allowed_users`).all<{ telegram_id: string }>();
  return (rows.results ?? []).map((r) => r.telegram_id);
}

export async function addAllowedUser(db: D1Database, telegramId: string, addedBy: string | null): Promise<void> {
  await db
    .prepare(`INSERT INTO allowed_users (telegram_id, added_by, created_at) VALUES (?, ?, ?)
              ON CONFLICT(telegram_id) DO NOTHING`)
    .bind(telegramId, addedBy, new Date().toISOString())
    .run();
}

export async function removeAllowedUser(db: D1Database, telegramId: string): Promise<boolean> {
  const result = await db
    .prepare(`DELETE FROM allowed_users WHERE telegram_id = ?`)
    .bind(telegramId)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

// ---------------------------------------------------------------------------
// Row mappers
// ---------------------------------------------------------------------------

function rowToTarget(r: Record<string, unknown>): Target {
  return {
    id: String(r["id"]),
    organization_id: String(r["organization_id"] ?? "default"),
    name: String(r["name"]),
    group_id: (r["group_id"] as string | null) ?? null,
    passive_only: true,
    low_impact_active: false,
    intrusive_enabled: false,
    max_request_rate_per_min: 60,
    max_concurrent_jobs: 1,
    program_rules_url: null,
    // The scope engine treats "confirmed" targets as authorized; Watchtower
    // targets are public bug bounty programs, so this is always confirmed.
    authorization_reference: "public-program",
    // Far-future expiry: targets never expire on their own (use /remove).
    authorization_expires_at: "9999-12-31T23:59:59.000Z",
    paused: String(r["status"] ?? "active") !== "active",
    created_at: String(r["created_at"]),
    created_by: (r["created_by"] as string | null) ?? null,
  };
}

function rowToTargetGroup(r: Record<string, unknown>): TargetGroup {
  return {
    id: String(r["id"]),
    name: String(r["name"]),
    organization_id: String(r["organization_id"] ?? "default"),
    created_at: String(r["created_at"]),
    created_by: (r["created_by"] as string | null) ?? null,
  };
}

function rowToScopeEntry(r: Record<string, unknown>): ScopeEntry {
  const active = String(r["status"] ?? "active") === "active";
  const denylist = !!r["is_denylist"];
  return {
    id: String(r["id"]),
    organization_id: String(r["organization_id"] ?? "default"),
    target_id: String(r["target_id"]),
    type: r["scope_type"] as ScopeEntry["type"],
    value: String(r["value"]),
    included: active && !denylist,
    notes: (r["notes"] as string | null) ?? null,
    created_at: String(r["created_at"]),
    expires_at: null,
    paused: String(r["status"]) === "paused",
    created_by: (r["created_by"] as string | null) ?? null,
  };
}
