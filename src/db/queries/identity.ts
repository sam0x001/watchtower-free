// src/db/queries/identity.ts
// Canonical identity helpers.
//
// The canonical schema splits identity (`users`) from authorization
// (`memberships` + `roles`), and every audit/created_by column is a real
// foreign key into `users(id)`. The Telegram layer only knows a Telegram user
// id, so commands resolve (or lazily create) the canonical rows through here.

import { randomId } from "../../crypto/hash.js";

export interface TelegramActor {
  id: number;
  first_name?: string;
  username?: string;
}

/** Canonical role names, ranked; anything unknown maps to the least privileged. */
export function normalizeRoleName(roleName: string): string {
  const r = (roleName ?? "").toLowerCase().replace(/-/g, "_");
  if (r === "owner") return "owner";
  if (r === "admin" || r === "administrator") return "administrator";
  if (r === "analyst") return "analyst";
  if (r === "external_reviewer" || r === "reviewer" || r === "external") return "external_reviewer";
  return "viewer";
}

/** `users.id` for a Telegram user id, or null when they were never bootstrapped. */
export async function findUserIdByTelegram(
  db: D1Database,
  telegramUserId: string | number,
): Promise<string | null> {
  const row = await db
    .prepare(`SELECT id FROM users WHERE telegram_user_id = ?`)
    .bind(String(telegramUserId))
    .first<{ id: string }>();
  return row?.id ?? null;
}

/**
 * `users.id` for the acting Telegram user, creating the canonical users row on
 * first contact. Required because `created_by`/`requested_by`/`actor_user_id`
 * are foreign keys.
 */
export async function ensureUserId(
  db: D1Database,
  actor: TelegramActor | null,
): Promise<string | null> {
  if (!actor) return null;
  const existing = await findUserIdByTelegram(db, actor.id);
  if (existing) return existing;
  const id = randomId("user", 12);
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO users (id, telegram_user_id, telegram_username, display_name, is_active, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, ?, ?, ?)`,
    )
    .bind(
      id,
      String(actor.id),
      actor.username ?? null,
      actor.first_name ?? `Telegram ${actor.id}`,
      now, now, now,
    )
    .run();
  return id;
}

/** `roles.id` for a canonical role name. */
export async function resolveRoleId(db: D1Database, roleName: string): Promise<string | null> {
  const row = await db
    .prepare(`SELECT id FROM roles WHERE name = ?`)
    .bind(normalizeRoleName(roleName))
    .first<{ id: string }>();
  return row?.id ?? null;
}

/** Target authorization window + owning organization (lookup by ID or name). */
export async function targetContext(
  db: D1Database,
  targetIdOrName: string,
): Promise<{ id: string; organization_id: string; valid_from: string; valid_until: string } | null> {
  const byId = await db
    .prepare(`SELECT id, organization_id, valid_from, valid_until FROM targets WHERE id = ?`)
    .bind(targetIdOrName)
    .first<{ id: string; organization_id: string; valid_from: string; valid_until: string }>();
  if (byId) return byId;
  const byName = await db
    .prepare(`SELECT id, organization_id, valid_from, valid_until FROM targets WHERE name = ?`)
    .bind(targetIdOrName)
    .first<{ id: string; organization_id: string; valid_from: string; valid_until: string }>();
  return byName ?? null;
}
