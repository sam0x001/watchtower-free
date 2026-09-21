// src/constants.ts
// Global constants. Keep these conservative — they can be tightened per
// target via scan profiles, but never loosened beyond these ceilings.

export const LIMITS = {
  MAX_RESPONSE_BYTES: 5 * 1024 * 1024,          // 5 MiB hard ceiling per HTTP fetch
  MAX_CERT_PROVIDER_RESPONSE_BYTES: 25 * 1024 * 1024, // 25 MiB ceiling for CT JSON
  MAX_JS_FILE_BYTES: 2 * 1024 * 1024,            // 2 MiB per JS file
  MAX_JS_FILES_PER_TARGET: 500,
  MAX_WORDLIST_ENTRIES: 50_000,
  MAX_WORDLIST_ENTRY_LENGTH: 256,
  MAX_REQUEST_TIMEOUT_MS: 30_000,
  MAX_CONCURRENT_SCANS: 5,
  MAX_CONCURRENT_HTTP_PER_HOST: 3,
  MAX_QUEUE_RETRIES: 5,
  MAX_AUDIT_RECORD_PER_COMMAND: 1,
  MAX_TELEGRAM_MESSAGE_BYTES: 3500,              // Telegram hard limit is 4096
  EVIDENCE_RETENTION_DAYS: 180,
  AUDIT_RETENTION_DAYS: 730,
  SCOPE_EXPIRY_WARNING_DAYS: 7,
  DEFAULT_RATE_LIMIT_PER_MINUTE: 60,
  EMERGENCY_STOP_TTL_HOURS: 24,
} as const;

// src/constants.ts
// Global constants. Keep these conservative — they can be tightened per
// target via scan profiles, but never loosened beyond these ceilings.
//
// NOTE: Severity, VerificationState, FindingStatus, ScanProfile types now
// live in src/types.ts (v2 consolidation). They are re-exported here for
// backwards compatibility with modules that import from constants.

export type { Severity, VerificationState, FindingStatus, ScanProfile } from "./types.js";

export const SEVERITY = {
  INFO: "informational",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export const SEVERITY_RANK: Record<"informational" | "low" | "medium" | "high" | "critical", number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const VERIFICATION_STATE = {
  DETECTED: "detected",
  SUSPECTED: "suspected",
  VERIFIED: "verified",
  CONFIRMED_HUMAN: "confirmed_human",
  FALSE_POSITIVE: "false_positive",
  REJECTED: "rejected",
} as const;

export const FINDING_STATUS = {
  OPEN: "open",
  ASSIGNED: "assigned",
  IN_REVIEW: "in_review",
  RESOLVED: "resolved",
  CLOSED: "closed",
  REOPENED: "reopened",
} as const;

export const SCAN_PROFILE = {
  PASSIVE_ONLY: "passive-only",
  LOW_IMPACT_WEB: "low-impact-web-content",
  LOW_IMPACT_API: "low-impact-api-discovery",
  JS_MONITORING: "javascript-monitoring",
  SUBDOMAIN_MONITORING: "subdomain-monitoring",
  TECH_SPECIFIC: "technology-specific",
  CUSTOM_AUTHORIZED: "custom-authorized",
  FULL_APPROVED: "full-approved-monitoring",
} as const;

export const HTTP_METHODS_SAFE = ["GET", "HEAD"] as const;
export const HTTP_METHODS_INTRUSIVE = ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"] as const;

// Banned destination networks for SSRF protection.
export const BLOCKED_CIDRS = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",          // CGNAT
  "127.0.0.0/8",
  "169.254.0.0/16",         // link-local
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",           // TEST-NET-1
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",        // TEST-NET-2
  "203.0.113.0/24",         // TEST-NET-3
  "224.0.0.0/4",            // multicast
  "240.0.0.0/4",            // reserved
  "255.255.255.255/32",     // broadcast
] as const;

export const BLOCKED_IPV6_CIDRS = [
  "::1/128",          // loopback
  "::/128",           // unspecified
  "::ffff:0:0/96",    // IPv4-mapped
  "fc00::/7",         // ULA
  "fe80::/10",        // link-local
  "ff00::/8",         // multicast
  "2001:db8::/32",    // documentation
] as const;

// Cloud metadata endpoints — never allow fetches here.
export const BLOCKED_HOSTNAMES = new Set([
  "169.254.169.254",            // AWS / GCP / Azure IMDS
  "metadata.google.internal",   // GCP metadata
  "metadata.azure.com",         // Azure metadata (IMDS uses 169.254.169.254 too)
  "fd00:ec2::254",              // AWS IMDS IPv6
]);

export const ALLOWED_PORTS = new Set([80, 443, 8080, 8443, 3000, 5000, 8000, 8888]);

// Telegram command surface
export const COMMANDS = [
  { command: "start",            description: "Initialize the bot and view the welcome screen" },
  { command: "help",            description: "List available commands" },
  { command: "authorize",        description: "Confirm target ownership or written testing permission" },
  { command: "scope_add",       description: "Add a new in-scope entry" },
  { command: "scope_list",      description: "List all configured scope entries" },
  { command: "scope_update",    description: "Update an existing scope entry" },
  { command: "scope_remove",    description: "Remove a scope entry" },
  { command: "scope_pause",     description: "Pause a scope entry" },
  { command: "scope_resume",    description: "Resume a paused scope entry" },
  { command: "scope_expire",    description: "Force-expire a scope entry" },
  { command: "target_add",      description: "Add a monitoring target" },
  { command: "target_list",     description: "List all targets" },
  { command: "target_details",  description: "View a target's details" },
  { command: "target_pause",    description: "Pause monitoring for a target" },
  { command: "target_resume",   description: "Resume monitoring for a target" },
  { command: "scan_passive",     description: "Run a passive scan" },
  { command: "scan_active",     description: "Run a low-impact active scan (requires approval)" },
  { command: "scan_status",     description: "View the status of in-flight scans" },
  { command: "scan_cancel",     description: "Cancel a scan" },
  { command: "scan_history",    description: "View scan history" },
  { command: "findings_list",   description: "List findings" },
  { command: "finding_details", description: "View a finding's details" },
  { command: "finding_verify",   description: "Mark a finding as verified" },
  { command: "finding_reject",   description: "Reject a finding as false positive" },
  { command: "finding_assign",   description: "Assign a finding to a user" },
  { command: "finding_close",    description: "Close a finding" },
  { command: "finding_reopen",   description: "Reopen a finding" },
  { command: "report_create",   description: "Generate a report" },
  { command: "report_export",   description: "Export a report as Markdown / JSON / PDF" },
  { command: "diff_latest",     description: "View the latest changes for a target" },
  { command: "diff_compare",    description: "Compare two snapshots" },
  { command: "alerts_enable",   description: "Enable alerts for a target" },
  { command: "alerts_disable",  description: "Disable alerts for a target" },
  { command: "schedule_add",    description: "Add a monitoring schedule" },
  { command: "schedule_list",   description: "List schedules" },
  { command: "schedule_remove", description: "Remove a schedule" },
  { command: "integration_add",    description: "Add a notification integration" },
  { command: "integration_remove", description: "Remove an integration" },
  { command: "settings",       description: "View and edit user settings" },
  { command: "team_invite",     description: "Invite a teammate" },
  { command: "team_members",   description: "List team members" },
  { command: "audit",          description: "View the audit log" },
  { command: "stop",           description: "EMERGENCY STOP — cancel all scheduled jobs" },
  { command: "resume",         description: "Resume after an emergency stop" },
] as const;
