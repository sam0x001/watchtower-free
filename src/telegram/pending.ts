// src/telegram/pending.ts
// Short-lived, per-chat state for the two commands that need a second step.
//
//   * /remove <category>  — deleting a category AND every domain under it is
//     destructive and irreversible, so it requires a confirm token. Without
//     this, one typo destroys a program's whole asset history.
//   * /scan <category>    — one inline discovery pass per member domain burns
//     several third-party CT/DNS calls each, so a category with many domains
//     is capped per invocation; the token says "scan the rest, please".
//
// Both live in the CACHE KV namespace under `pending:<chatId>:<action>`, with
// a short TTL. Nothing here is authoritative state — losing an entry only means
// the operator has to retype the command, so KV (rather than D1) is the right
// home for it: it costs a read, not a row.

import type { Env } from "../env.js";

/** `/remove` confirmations stay valid for 10 minutes. */
export const REMOVE_CONFIRM_TTL_SECONDS = 600;

/** How many category members one `/scan` invocation scans before deferring. */
export const SCAN_GROUP_BATCH = 5;

export interface RemoveConfirmation {
  groupId: string;
  groupName: string;
  /** Domains (and their stored findings) this confirmation will destroy. */
  domainCount: number;
  createdAt: string;
}

export async function saveRemoveConfirmation(
  env: Env,
  chatId: number,
  confirmation: RemoveConfirmation,
): Promise<string> {
  const token = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  await env.CACHE.put(`pending:${chatId}:remove`, JSON.stringify({ ...confirmation, token }), {
    expirationTtl: REMOVE_CONFIRM_TTL_SECONDS,
  });
  return token;
}

export async function readRemoveConfirmation(
  env: Env,
  chatId: number,
  token: string,
): Promise<RemoveConfirmation | null> {
  const raw = await env.CACHE.get(`pending:${chatId}:remove`).catch(() => null);
  if (!raw) return null;
  let stored: RemoveConfirmation & { token?: string };
  try {
    stored = JSON.parse(raw) as RemoveConfirmation & { token?: string };
  } catch {
    return null;
  }
  // The token is the confirmation: an attacker who can type in the chat but
  // cannot read it cannot destroy anything by guessing.
  if (stored.token !== token) return null;
  return { groupId: stored.groupId, groupName: stored.groupName, domainCount: stored.domainCount, createdAt: stored.createdAt };
}

export async function clearRemoveConfirmation(env: Env, chatId: number): Promise<void> {
  await env.CACHE.delete(`pending:${chatId}:remove`).catch(() => undefined);
}

// ---------------------------------------------------------------------------
// /scan <category> — batch continuation
// ---------------------------------------------------------------------------

export interface ScanGroupContinuation {
  groupId: string;
  groupName: string;
  /** Members still to scan, oldest first. */
  pending: string[];
  scanned: number;
  createdAt: string;
}

export async function saveScanContinuation(
  env: Env,
  chatId: number,
  continuation: ScanGroupContinuation,
): Promise<void> {
  // A continuation is an offer, not a queue entry: a day is long enough to
  // cover the cron ticks that finish the work anyway.
  await env.CACHE.put(`pending:${chatId}:scan`, JSON.stringify(continuation), {
    expirationTtl: 86_400,
  }).catch(() => undefined);
}

export async function readScanContinuation(
  env: Env,
  chatId: number,
  groupId: string,
): Promise<ScanGroupContinuation | null> {
  const raw = await env.CACHE.get(`pending:${chatId}:scan`).catch(() => null);
  if (!raw) return null;
  try {
    const stored = JSON.parse(raw) as ScanGroupContinuation;
    return stored.groupId === groupId ? stored : null;
  } catch {
    return null;
  }
}

export async function clearScanContinuation(env: Env, chatId: number): Promise<void> {
  await env.CACHE.delete(`pending:${chatId}:scan`).catch(() => undefined);
}
