// src/scope/index.ts
// Scope engine entry point. Wraps the default-deny matcher in `match.ts`
// (deny-beats-allow, wildcard handling, private-IP blocking) with a compiled
// scope built from D1 rows.
//
// Targets added through the bot are always "confirmed" — Watchtower is meant
// for public bug bounty programs, so there is no authorization workflow.

import {
  evaluateScope,
  parseAsset,
  isBlockedIp,
  isMetadataAddress,
  isWildcardTooBroad,
  type ScopeRecord,
  type EvaluateScopeOptions,
} from "./match.js";
import type { ScopeEntry, Target } from "../types.js";

// ---------------------------------------------------------------------------
// The "compiled scope" consumed by callers: the runtime shape that
// `evaluateScope` accepts, plus target-level metadata.
// ---------------------------------------------------------------------------

export interface CompiledScope {
  targetId: string;
  records: ScopeRecord[];
  target: EvaluateScopeOptions["target"];
  emergencyStop: boolean;
}

/** Build a `CompiledScope` from already-loaded D1 rows. */
export function compileScope(target: Target, scopeEntries: ScopeEntry[]): CompiledScope {
  const records: ScopeRecord[] = scopeEntries
    .map((e) => scopeEntryToRecord(e))
    .filter((r): r is ScopeRecord => r !== null);

  return {
    targetId: target.id,
    records,
    target: {
      status: target.paused ? "paused" : "active",
      authorizationStatus: "confirmed",
      validFrom: null,
      validUntil: null,
      passiveOnly: target.passive_only,
      lowImpactActive: target.low_impact_active,
      intrusiveEnabled: target.intrusive_enabled,
    },
    emergencyStop: false,
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

  const now = opts.now ?? new Date();
  if (compiled.target?.validUntil && now.getTime() >= Date.parse(compiled.target.validUntil)) {
    return { allowed: false, reason: "expired" };
  }
  if (compiled.target?.validFrom && now.getTime() < Date.parse(compiled.target.validFrom)) {
    return { allowed: false, reason: "expired" };
  }

  // A target with no allowlist row at all is simply not configured yet.
  if (!compiled.records.some((r) => r.isAllowlist)) {
    return { allowed: false, reason: "no_scope" };
  }

  const decision = evaluateScope(host, compiled.records, {
    now,
    target: compiled.target ?? undefined,
    emergencyStop: compiled.emergencyStop,
  });
  if (decision.allowed) return { allowed: true, reason: "ok" };

  // Hard-coded refusals (private ranges, metadata endpoints) are reported
  // distinctly — they are never a scope decision, whatever the validation says.
  if (isBlockedIp(host)) return { allowed: false, reason: "blocked_ip_range" };
  if (isMetadataAddress(host)) return { allowed: false, reason: "blocked_metadata" };

  switch (decision.validation) {
    case "out_of_scope":
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
  // parseAsset accepts URLs and extracts the host internally.
  return checkHostInScope(compiled, url, opts);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function isScopeExpired(target: Target, now: Date = new Date()): boolean {
  return new Date(target.authorization_expires_at).getTime() < now.getTime();
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
    organizationId: e.organization_id,
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
  isMetadataAddress,
  isWildcardTooBroad,
} from "./match.js";
export type { ScopeRecord, ScopeRule, ParsedAsset, EvaluateScopeOptions } from "./match.js";
