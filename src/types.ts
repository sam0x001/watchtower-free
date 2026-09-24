// src/types.ts
// Shared domain types for the Watchtower worker.
//
// Mirrors the D1 schema in ./migrations. Anything that crosses a module
// boundary (Telegram, queue messages, provider adapters) is typed here so a
// single place defines the contract.

// ===========================================================================
// Severity + verification
// ===========================================================================

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: readonly Severity[] = [
  "informational", "low", "medium", "high", "critical",
] as const;

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? 0 : index;
}

export function severityAtLeast(value: Severity, threshold: Severity): boolean {
  return severityRank(value) >= severityRank(threshold);
}

export type VerificationState =
  | "detected"
  | "suspected"
  | "verified"
  | "false_positive";

// ===========================================================================
// Scope
// ===========================================================================

export type ScopeType =
  | "domain"
  | "wildcard_domain"
  | "ip"
  | "cidr"
  | "url"
  | "api";

export type ScopeStatus = "active" | "paused" | "expired" | "removed";
export type TargetStatus = "active" | "paused" | "expired" | "archived";
export type AuthorizationStatus = "pending" | "confirmed" | "revoked" | "expired";

/** How intrusive a request is allowed to be. The bot only ever runs passive work. */
export type ScanMode = "passive" | "low_impact_active" | "intrusive";

/** Result of validating an asset string against an authorized scope set. */
export type ScopeValidation = "pending" | "in_scope" | "out_of_scope" | "expired" | "denied";

export interface ScopeDecision {
  allowed: boolean;
  reason: string;
  /** Which scope row authorized the asset, when allowed. */
  scopeId?: string;
  validation: ScopeValidation;
  /** Resolved ports the scope permits, if constrained. */
  allowedPorts?: number[];
  deniedPorts?: number[];
}

/**
 * A scope row as stored in D1. `included` is false for denylist entries.
 */
export interface ScopeEntry {
  id: string;
  organization_id: string;
  target_id: string;
  type: ScopeType;
  value: string;
  included: boolean;
  notes: string | null;
  created_at: string;
  expires_at: string | null;
  paused: boolean;
  /** Telegram id of whoever created the entry (optional in fixtures). */
  created_by?: string | null;
}

/**
 * The in-memory target shape consumed by the scope engine and scan pipeline.
 * `authorization_*` fields are kept for scope-engine compatibility; targets
 * added through the bot are always confirmed (public bug bounty programs).
 */
export interface Target {
  id: string;
  organization_id: string;
  name: string;
  /** Owning group id, or null/undefined for standalone (pre-group) targets. */
  group_id?: string | null;
  passive_only: boolean;
  low_impact_active: boolean;
  intrusive_enabled: boolean;
  max_request_rate_per_min: number;
  max_concurrent_jobs: number;
  program_rules_url: string | null;
  authorization_reference: string;
  authorization_expires_at: string;
  paused: boolean;
  created_at: string;
  created_by?: string | null;
}

/** A named bucket of domains scanned under one id (see /target_add). */
export interface TargetGroup {
  id: string;
  name: string;
  organization_id: string;
  created_at: string;
  created_by?: string | null;
}

// ===========================================================================
// Notifications
// ===========================================================================

export type NotificationChannel = "telegram";

export interface NotificationMessage {
  organization_id: string;
  target_id: string | null;
  finding_id?: string | null;
  channel: NotificationChannel;
  severity: Severity;
  payload: {
    title?: string;
    summary?: string;
    change_type?: string;
    target_id?: string;
    target_name?: string;
    [key: string]: unknown;
  };
}

// ===========================================================================
// Queue messages
// ===========================================================================

export interface ScanMessage {
  job_id: string;
  target_id: string;
  organization_id: string;
  profile: string;
  triggered_by: "telegram" | "cron" | "continuation";
  triggered_by_user_id: string | null;
  chat_id?: number | null;
  attempt: number;
  enqueued_at: string;
}

export type QueueMessage = ScanMessage | NotificationMessage;
