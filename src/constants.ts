// src/constants.ts
// Global constants. Conservative ceilings so the free tier is never exceeded.

export const LIMITS = {
  MAX_RESPONSE_BYTES: 5 * 1024 * 1024,          // 5 MiB hard ceiling per HTTP fetch
  MAX_CERT_PROVIDER_RESPONSE_BYTES: 25 * 1024 * 1024, // 25 MiB ceiling for CT JSON
  MAX_JS_FILE_BYTES: 2 * 1024 * 1024,            // 2 MiB per JS file
  MAX_JS_FILES_PER_TARGET: 50,
  MAX_WORDLIST_ENTRY_LENGTH: 256,
  MAX_REQUEST_TIMEOUT_MS: 30_000,
  MAX_CONCURRENT_SCANS: 5,
  MAX_QUEUE_RETRIES: 5,
  MAX_TELEGRAM_MESSAGE_BYTES: 3500,              // Telegram hard limit is 4096
  NOTIFICATION_DEDUPE_WINDOW_HOURS: 24 * 7,      // a change is reported once per week
  JOB_RETENTION_DAYS: 7,
  NOTIFICATION_RETENTION_DAYS: 30,
} as const;

export const SEVERITY = {
  INFO: "informational",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

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

// Telegram command surface — the entire UX of the bot.
// Command names must be [a-zA-Z0-9_] only: Telegram rejects "-" in
// setMyCommands, so multi-word commands use "_" (e.g. /target_add). Keep the
// examples below in that same form — the menu only autocompletes what we print.
export const COMMANDS = [
  { command: "start",   description: "Initialize the bot and view the welcome screen" },
  { command: "help",    description: "List available commands" },
  { command: "target_add", description: "Create a target category, e.g. /target_add shop" },
  { command: "target_info", description: "Show a category and its domains: /target_info <category>" },
  { command: "add",     description: "Add a domain to monitor: /add <domain> [category]" },
  { command: "exclude", description: "Exclude a subdomain/path from scanning, e.g. /exclude sub.example.com" },
  { command: "scan",    description: "Scan a category or domain now, e.g. /scan shop" },
  { command: "feature", description: "List or toggle a domain's monitoring features: /feature <domain> [key on|off]" },
  { command: "list",    description: "List categories, domains, exclusions and asset counts" },
  { command: "remove",  description: "Stop a domain or a whole category, e.g. /remove example.com" },
  { command: "allow",   description: "Allow another Telegram user to use this bot: /allow <telegram_id>" },
  { command: "disallow", description: "Revoke a user's access: /disallow <telegram_id>" },
] as const;
