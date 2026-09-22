// src/types.ts
// Watchtower shared domain types.
//
// Mirrors the D1 schema in ./migrations. Anything that crosses a module
// boundary (Telegram, API, queue messages, provider adapters, runner
// protocol) is typed here so a single place defines the contract.
//
// Merged from watchtower1's richer taxonomy + the legacy types the
// rest of the codebase was originally written against.

// ===========================================================================
// Severity + verification + status enums
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

export type ScanMode = "passive" | "low_impact_active" | "intrusive";

export type ScopeType =
  | "domain"
  | "wildcard_domain"
  | "ip"
  | "cidr"
  | "url"
  | "api"
  | "repository"
  | "cloud_account"
  | "mobile_app";

export type ScopeStatus = "active" | "paused" | "expired" | "removed";
export type TargetStatus = "active" | "paused" | "expired" | "archived";
export type AuthorizationStatus = "pending" | "confirmed" | "revoked" | "expired";
export type AuthorizationType =
  | "written_permission"
  | "bug_bounty_program"
  | "internal_mandate"
  | "vendor_contract";

export type VerificationState =
  | "detected"
  | "suspected"
  | "verified"
  | "confirmed_human"
  | "false_positive"
  | "rejected";

export type FindingStatus =
  | "open"
  | "assigned"
  | "in_review"
  | "resolved"
  | "closed"
  | "reopened"
  | "triaged"
  | "in_progress"
  | "suppressed"
  | "duplicate";

export type ScopeValidation = "pending" | "in_scope" | "out_of_scope" | "expired" | "denied";

export type ScanProfile =
  | "passive-only"
  | "low-impact-web-content"
  | "low-impact-api-discovery"
  | "javascript-monitoring"
  | "subdomain-monitoring"
  | "technology-specific"
  | "custom-authorized"
  | "full-approved-monitoring";

export type RunnerKind =
  | "container"
  | "github_action"
  | "cloud_run"
  | "fly_io"
  | "aws_batch"
  | "lambda_container"
  | "self_hosted"
  | "browser_runner";

export type RunnerStatus = "pending" | "active" | "degraded" | "revoked" | "unhealthy";

/** Allow-listed external tools. Never accept an arbitrary tool name. */
export type RunnerTool =
  | "nmap"
  | "subfinder"
  | "amass"
  | "httpx"
  | "nuclei"
  | "burp"
  | "zap"
  | "cloud_scanner"
  | "screenshot"
  | "report_renderer";

export type ChangeCategory =
  | "asset"
  | "dns"
  | "certificate"
  | "service"
  | "http"
  | "javascript"
  | "api"
  | "technology"
  | "vulnerability"
  | "secret"
  | "scope"
  | "availability"
  | "exposure";

export type ChangeReviewState =
  | "unreviewed"
  | "expected"
  | "suppressed"
  | "confirmed"
  | "false_positive"
  | "needs_review";

export type NotificationChannel =
  | "telegram"
  | "slack"
  | "email"
  | "jira"
  | "github"
  | "webhook"
  | "digest";

export type AlertType =
  | "new_subdomain"
  | "new_ip"
  | "new_certificate"
  | "dns_change"
  | "technology_change"
  | "javascript_change"
  | "api_endpoint_change"
  | "new_vulnerability"
  | "severity_increase"
  | "secret_candidate"
  | "scope_violation"
  | "outage"
  | "scanner_failure"
  | "runner_failure"
  | "authorization_expiring"
  | "certificate_expiring"
  | "scheduled_report"
  | "emergency_stop";

// ===========================================================================
// RBAC
// ===========================================================================

export type RoleName = "owner" | "administrator" | "analyst" | "viewer" | "external_reviewer";

export interface Requester {
  userId: string;
  organizationId: string;
  roleId: string;
  roleName: RoleName;
  telegramUserId: string;
  capabilities: string[];
}

// ===========================================================================
// Scope
// ===========================================================================

/** Result of validating an asset string against an authorized scope set. */
export interface ScopeDecision {
  allowed: boolean;
  reason: string;
  /** Which scope row authorized the asset, when allowed. */
  scopeId?: string;
  validation: ScopeValidation;
  /** Resolved ports/paths the scope permits, if constrained. */
  allowedPorts?: number[];
  deniedPorts?: number[];
}

// ===========================================================================
// Domain models (DB row shapes)
// ===========================================================================

export interface Organization {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export interface User {
  id: string;
  telegram_id: string | null;
  api_token_hash: string | null;
  display_name: string;
  role: RoleName;
  organization_id: string;
  created_at: string;
  last_active_at: string | null;
  deactivated_at: string | null;
}

export interface ScopeEntry {
  id: string;
  target_id: string;
  type: ScopeType;
  value: string;
  included: boolean; // true = allowlist, false = denylist
  notes: string | null;
  created_at: string;
  expires_at: string | null;
  paused: boolean;
}

export interface Target {
  id: string;
  organization_id: string;
  name: string;
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
}

export interface ScanJob {
  id: string;
  target_id: string;
  organization_id: string;
  profile: ScanProfile;
  triggered_by: "cron" | "telegram" | "api" | "runner";
  triggered_by_user_id: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  payload_hash: string | null;
}

export interface Finding {
  id: string;
  organization_id: string;
  target_id: string;
  asset_id: string | null;
  type: string;
  title: string;
  summary: string;
  technical_description: string;
  business_impact: string | null;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  cwe: string | null;
  cve: string | null;
  owasp_category: string | null;
  affected_url: string | null;
  detection_source: string;
  detection_method: string;
  confidence: number; // 0..1
  status: FindingStatus;
  assigned_user_id: string | null;
  verification_state: VerificationState;
  scope_validation_state: ScopeValidation;
  remediation: string | null;
  retest_status: "not_required" | "requested" | "in_progress" | "passed" | "failed" | null;
  duplicate_of: string | null;
  attack_chain_id: string | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  target_id: string;
  type: "subdomain" | "ip" | "url" | "service" | "javascript" | "api_endpoint" | "certificate" | "cloud_resource";
  value: string;
  normalized: string;
  first_seen: string;
  last_seen: string;
  scope_status: "in_scope" | "out_of_scope" | "unknown";
  metadata_json: string;
}

export interface DnsRecord {
  id: string;
  asset_id: string;
  type: string;
  name: string;
  value: string;
  ttl: number | null;
  first_seen: string;
  last_seen: string;
  removed_at: string | null;
}

export interface Certificate {
  id: string;
  asset_id: string;
  issuer: string;
  serial: string;
  not_before: string | null;
  not_after: string | null;
  sans_json: string;
  first_seen: string;
  last_seen: string;
  removed_at: string | null;
}

export interface ScanMessage {
  job_id: string;
  target_id: string;
  organization_id: string;
  profile: ScanProfile | string;
  triggered_by: "cron" | "telegram" | "api" | "runner";
  triggered_by_user_id: string | null;
  attempt: number;
  enqueued_at: string;
}

export interface NotificationMessage {
  organization_id: string;
  target_id: string | null;
  finding_id?: string;
  change_id?: string;
  channel: NotificationChannel;
  severity: Severity;
  payload: Record<string, unknown>;
  dedup_key: string;
  attempt: number;
}

export interface ReportMessage {
  report_id: string;
  organization_id: string;
  correlation_id: string;
}

export type QueueMessage = ScanMessage | NotificationMessage | ReportMessage;

/** Actor classification stored in `audit_logs.actor_kind` (see migrations/0001_initial.sql). */
export type AuditActorKind = "telegram" | "api" | "system" | "runner" | "webhook";

export interface AuditEvent {
  timestamp: string;
  user_id: string | null;
  telegram_id: string | null;
  organization_id: string | null;
  action: string;
  target_id: string | null;
  scope_id: string | null;
  job_id: string | null;
  scanner: string | null;
  args_redacted: string;
  /**
   * In-memory result vocabulary. The audit_logs table stores a narrower set
   * ('success' | 'denied' | 'error' | 'pending_approval'): the logger maps
   * "failure" -> "error" and "blocked" -> "denied" when writing.
   */
  result: "success" | "failure" | "blocked" | "denied" | "pending_approval";
  error: string | null;
  ip: string | null;
  request_id: string;
  /**
   * Who performed the action. Optional — when omitted the logger infers the
   * kind from the action prefix / presence of a telegram id. It is never
   * omitted in the INSERT because `audit_logs.actor_kind` is NOT NULL.
   */
  actor_kind?: AuditActorKind;
  /** Raw actor identifier (Telegram id, user id, runner id...). Defaults to telegram_id/user_id. */
  actor_identity?: string | null;
  /** Runner id, when the action was performed by (or on behalf of) a runner. */
  runner_id?: string | null;
}

export interface RunnerRegistration {
  runner_id: string;
  name: string;
  owner_user_id: string;
  pubkey: string;
  created_at: string;
  last_seen: string | null;
  revoked: boolean;
  allowed_tools: string[];
  network_egress_allowlist: string[];
}

export interface RunnerJobPayload {
  job_id: string;
  scan_job_id: string;
  target_id: string;
  tool: string;
  args: Record<string, string | number | boolean | string[]>;
  scope_fingerprint: string;
  max_runtime_seconds: number;
  max_output_bytes: number;
  created_at: string;
  expires_at: string;
  signature: string;
}

export interface DiffResult {
  type: "added" | "removed" | "changed";
  path: string;
  before: unknown;
  after: unknown;
  confidence: number;
  severity: Severity | null;
  volatile: boolean;
}

export interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  request_id: string;
}

export interface EvidenceDescriptor {
  key: string;
  contentHash: string;
  sizeBytes: number;
  contentType: string;
  encrypted: boolean;
  integrityHash: string;
  retentionDays: number;
  createdAt: string;
}

export interface JsonLogFields {
  event: string;
  [key: string]: unknown;
}

// ===========================================================================
// Telegram command catalogue
// ===========================================================================

export type CommandName =
  | "start" | "help" | "authorize" | "resume" | "stop"
  | "scope_add" | "scope_list" | "scope_update" | "scope_remove" | "scope_pause" | "scope_resume" | "scope_expire"
  | "target_add" | "target_list" | "target_details" | "target_pause" | "target_resume"
  | "scan_passive" | "scan_active" | "scan_status" | "scan_cancel" | "scan_history"
  | "findings_list" | "finding_details" | "finding_verify" | "finding_reject"
  | "finding_assign" | "finding_close" | "finding_reopen"
  | "report_create" | "report_export"
  | "diff_latest" | "diff_compare"
  | "alerts_enable" | "alerts_disable"
  | "schedule_add" | "schedule_list" | "schedule_remove"
  | "integration_add" | "integration_remove"
  | "settings" | "team_invite" | "team_members" | "audit";

/** Parsed Telegram invocation: `/scope add example.com --type domain`. */
export interface ParsedCommand {
  name: CommandName;
  args: string[];
  flags: Record<string, string | boolean>;
  raw: string;
}

export type RunnerJobStatus =
  | "issued"
  | "acknowledged"
  | "running"
  | "completed"
  | "failed"
  | "expired"
  | "revoked";

export type DeadLetterQueue =
  | "watchtower-scan-jobs"
  | "watchtower-notifications"
  | "watchtower-reports-queue";
