// src/env.ts
// Strongly-typed bindings for the Watchtower Cloudflare Worker (FREE TIER).
//
// Free-tier constraints (https://developers.cloudflare.com/workers/platform/limits/):
//   - NO Queues  → async work runs via ctx.waitUntil() inside the cron handler
//   - NO Durable Objects → replaced with D1 row state (see src/db/)
//   - 1 Cron Trigger max → see src/cron/handler.ts for time-of-day dispatch
//   - 10ms CPU per invocation → scan work is bounded + chunked
//   - 100k Worker requests/day → fine for 5-min cron + occasional Telegram msgs
//   - D1: 5M reads + 100k writes per day, 5 GB total storage
//   - R2: 10 GB storage, 1M Class A operations, 10M Class B operations per month
//   - KV: 100k reads + 1k writes per day
//
// On the free tier, the latency budget is:
//   Cron tick every 5 min → claim pending jobs → run scan work in waitUntil()
//   → enqueue alerts as D1 job rows → next cron tick delivers them.
//   Total alert latency: typically 5–10 minutes (same as paid tier for low volume).

export interface Env {
  // ---- Cloudflare bindings ----------------------------------------------
  DB: D1Database;
  CACHE: KVNamespace;

  // ---- Optional R2 bindings (not required on free tier) -----------------
  // If set, evidence + reports will be stored in R2. If not set, they fall
  // back to D1 BLOB storage (see src/evidence/d1-storage.ts).
  EVIDENCE?: R2Bucket;
  REPORTS?: R2Bucket;

  // ---- Secrets ----------------------------------------------------------
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  AUTHORIZED_TELEGRAM_IDS: string; // comma-separated
  ENCRYPTION_KEY: string; // base64 32 bytes
  REDACTION_SALT: string; // random value used to salt secret fingerprints
  API_HMAC_KEY: string;
  WEBHOOK_SIGNING_SECRET: string;
  RUNNER_REGISTRY_TOKEN: string;

  // ---- Optional integrations -------------------------------------------
  SLACK_BOT_TOKEN?: string;
  JIRA_API_TOKEN?: string;
  JIRA_BASE_URL?: string;
  GITHUB_TOKEN?: string;
  GITHUB_REPO?: string;
  SENDGRID_API_KEY?: string;
  SENDGRID_FROM?: string;
  OSV_API_KEY?: string;
  NVD_API_KEY?: string;

  // ---- Runtime vars (from wrangler.toml [vars]) ------------------------
  WATCHTOWER_ENV: "dev" | "staging" | "production";
  MAX_RESPONSE_BYTES: string;
  MAX_JS_FILE_BYTES: string;
  MAX_JS_FILES_PER_ASSET: string;
  MAX_CERTIFICATE_RESULTS: string;
  MAX_WORDLIST_ENTRIES: string;
  MAX_WORDLIST_WORD_LENGTH: string;
  DEFAULT_REQUEST_TIMEOUT_MS: string;
  MAX_JOBS_PER_TARGET: string;
  GLOBAL_RATE_LIMIT_PER_MINUTE: string;
  TELEGRAM_UPDATE_MAX_BYTES: string;
  REQUIRE_HUMAN_APPROVAL_DEFAULT: string;
  PASSIVE_ONLY_DEFAULT: string;
  INTRUSIVE_TESTING_ENABLED: string;
  WORDLIST_MODULE_ENABLED: string;
  EVIDENCE_RETENTION_DAYS: string;
  JS_SNAPSHOT_RETENTION_DAYS: string;
  AUDIT_RETENTION_DAYS: string;
  ALERT_BATCH_LOW_SEVERITY: string;
  USER_AGENT: string;
  SCOPE_EXPIRY_WARNING_DAYS: string;
  // Free-tier overrides
  FREE_TIER_MAX_CPU_MS: string;        // hard ceiling — must be < 10ms on free
  FREE_TIER_MAX_JOBS_PER_CRON: string; // batch size for each cron invocation
  FREE_TIER_SCAN_TIMEOUT_MS: string;   // abort scans that exceed this
}

export const num = (v: string | undefined, fallback: number): number => {
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};
