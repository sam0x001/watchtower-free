// src/scope/index.ts
// Compatibility shim — exposes the same surface the rest of the codebase
// was written against (`compileScope`, `checkHostInScope`, `checkUrlInScope`,
// `isScopeExpired`, `scopeExpiringSoon`) but routes everything through
// watchtower1's more thorough `evaluateScope()` engine in `match.ts`.

import {
  evaluateScope,
  parseAsset,
  isBlockedIp,
  isWildcardTooBroad,
  type ScopeRecord,
  type EvaluateScopeOptions,
} from "./match.js";
import { loadScopeSnapshot, type ScopeLoaderEnv, type ScopeSnapshot } from "./loader.js";
import type { ScopeEntry, Target } from "../types.js";

// ---------------------------------------------------------------------------
// The "compiled scope" used by callers in this codebase is just the runtime
// shape that `evaluateScope` consumes, plus the target authorization metadata
// needed to evaluate time/authorization gates.
// ---------------------------------------------------------------------------

export interface CompiledScope {
  targetId: string;
  /** The D1-loaded snapshot (target + scopes + emergencyStop). */
  snapshot: ScopeSnapshot | null;
  /** In-memory snapshot (used when scope was passed by callers, not loaded). */
  records: ScopeRecord[];
  target: EvaluateScopeOptions["target"];
  emergencyStop: boolean;
}

/**
 * Build a `CompiledScope` from already-loaded D1 rows. Used by callers that
 * already have `ScopeEntry[]` in hand (e.g., from `listScopeEntries()`).
 */
export function compileScope(target: Target, scopeEntries: ScopeEntry[]): CompiledScope {
  const records: ScopeRecord[] = scopeEntries
    .map((e) => scopeEntryToRecord(e))
    .filter((r): r is ScopeRecord => r !== null);

  return {
    targetId: target.id,
    snapshot: null,
    records,
    target: {
      status: target.paused ? "paused" : "active",
      authorizationStatus: target.authorization_reference ? "confirmed" : "pending",
      validFrom: null,
      validUntil: target.authorization_expires_at,
      passiveOnly: target.passive_only,
      lowImpactActive: target.low_impact_active,
      intrusiveEnabled: target.intrusive_enabled,
    },
    emergencyStop: false,
  };
}

/**
 * Loads a `CompiledScope` directly from D1. This is the path used by queue
 * consumers and cron handlers that don't already have the rows in memory.
 * Uses watchtower1's fail-closed loader.
 */
export async function loadCompiledScope(env: ScopeLoaderEnv, targetId: string): Promise<CompiledScope> {
  const snapshot = await loadScopeSnapshot(env, targetId);
  return {
    targetId,
    snapshot,
    records: snapshot.scopes,
    target: snapshot.target
      ? {
          status: snapshot.target.status ?? "active",
          authorizationStatus: snapshot.target.authorizationStatus ?? "pending",
          validFrom: snapshot.target.validFrom,
          validUntil: snapshot.target.validUntil,
          passiveOnly: snapshot.target.passiveOnly,
          lowImpactActive: snapshot.target.lowImpactActive,
          intrusiveEnabled: snapshot.target.intrusiveEnabled,
        }
      : null,
    emergencyStop: snapshot.emergencyStop,
  };
}

// ---------------------------------------------------------------------------
// Host / URL scope checks — thin wrappers around `evaluateScope`.
// ---------------------------------------------------------------------------

export interface ScopeCheckResult {
  allowed: boolean;
  reason:
    | "ok"
    | "no_scope"
    | "expired"
    | "paused"
    | "missing_authorization"
    | "out_of_scope"
    | "denied_by_denylist"
    | "wildcard_too_broad"
    | "blocked_ip_range"
    | "blocked_metadata"
    | "ambiguous"
    | "target_paused"
    | "emergency_stop";
  matched?: ScopeEntry;
}

export interface CheckHostOptions {
  allowPrivate?: boolean;
  now?: Date;
}

export function checkHostInScope(
  compiled: CompiledScope,
  host: string,
  opts: CheckHostOptions = {},
): ScopeCheckResult {
  if (compiled.emergencyStop) {
    return { allowed: false, reason: "emergency_stop" };
  }
  if (compiled.target?.status === "paused") {
    return { allowed: false, reason: "target_paused" };
  }
  if (compiled.target?.authorizationStatus && compiled.target.authorizationStatus !== "confirmed") {
    return { allowed: false, reason: "missing_authorization" };
  }
  const now = opts.now ?? new Date();
  if (compiled.target?.validUntil && now.getTime() >= Date.parse(compiled.target.validUntil)) {
    return { allowed: false, reason: "expired" };
  }
  if (compiled.target?.validFrom && now.getTime() < Date.parse(compiled.target.validFrom)) {
    return { allowed: false, reason: "expired" };
  }

  // Watchtower1's parseAsset also handles IP-literal blocking + private ranges.
  const decision = evaluateScope(host, compiled.records, {
    now,
    target: compiled.target ?? undefined,
    emergencyStop: compiled.emergencyStop,
  });
  if (decision.allowed) return { allowed: true, reason: "ok" };

  // Translate watchtower1's validation enum to ours.
  switch (decision.validation) {
    case "out_of_scope":
      // Could be a blocked IP, metadata, or genuinely not in scope.
      if (isBlockedIp(host)) return { allowed: false, reason: "blocked_ip_range" };
      return { allowed: false, reason: "out_of_scope" };
    case "expired":
      return { allowed: false, reason: "expired" };
    case "denied":
      return { allowed: false, reason: "denied_by_denylist" };
    case "in_scope":
      return { allowed: true, reason: "ok" };
    default:
      return { allowed: false, reason: "ambiguous" };
  }
}

export function checkUrlInScope(
  compiled: CompiledScope,
  url: string,
  opts: CheckHostOptions = {},
): ScopeCheckResult {
  // Watchtower1's parseAsset accepts URLs and extracts the host internally.
  return checkHostInScope(compiled, url, opts);
}

// ---------------------------------------------------------------------------
// Authorization expiry helpers (used by cron + scan-consumer).
// ---------------------------------------------------------------------------

export function isScopeExpired(target: Target, now: Date = new Date()): boolean {
  return new Date(target.authorization_expires_at).getTime() < now.getTime();
}

export function scopeExpiringSoon(target: Target, warningDays: number, now: Date = new Date()): boolean {
  const exp = new Date(target.authorization_expires_at).getTime();
  const delta = exp - now.getTime();
  return delta > 0 && delta < warningDays * 86_400_000;
}

export function isWildcardPattern(input: string): boolean {
  return isWildcardTooBroad(input) === false && input.trim().startsWith("*.");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function scopeEntryToRecord(e: ScopeEntry): ScopeRecord | null {
  if (e.paused) return null;
  return {
    id: e.id,
    organizationId: "",
    targetId: e.target_id,
    scopeType: e.type,
    value: e.value,
    label: e.value,
    status: e.expires_at && new Date(e.expires_at).getTime() < Date.now() ? "expired" : "active",
    isAllowlist: e.included,
    passiveOnly: true,
    lowImpactActive: false,
    intrusiveEnabled: false,
    validFrom: null,
    validUntil: e.expires_at,
    rules: [],
  };
}

// Re-export the low-level primitives so callers can use them directly.
export {
  evaluateScope,
  parseAsset,
  isBlockedIp,
  isWildcardTooBroad,
} from "./match.js";
export { loadScopeSnapshot as loadScope } from "./loader.js";
export type { ScopeRecord, ScopeRule, ParsedAsset, EvaluateScopeOptions } from "./match.js";
export type { ScopeSnapshot, TargetAuthorizationState } from "./loader.js";
