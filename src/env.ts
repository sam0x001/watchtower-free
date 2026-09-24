// src/env.ts
// Strongly-typed bindings for the Watchtower Cloudflare Worker (FREE TIER).
//
// Free-tier constraints (https://developers.cloudflare.com/workers/platform/limits/):
//   - NO Queues  → async work runs via ctx.waitUntil() inside the cron handler
//   - NO Durable Objects → replaced with D1 row state (see src/db/)
//   - 1 Cron Trigger max → see src/cron/handler.ts
//   - 100k Worker requests/day, D1: 5M reads + 100k writes/day, KV: 100k reads
//     + 1k writes/day — all comfortably above what a personal monitoring bot needs.

export interface Env {
  // ---- Cloudflare bindings ----------------------------------------------
  DB: D1Database;
  CACHE: KVNamespace;

  // ---- Secrets ----------------------------------------------------------
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  /** Comma-separated bootstrap allowlist. Extendable at runtime via /allow. */
  AUTHORIZED_TELEGRAM_IDS?: string;
  /** Salt for secret fingerprints (values are never stored, only hashes). */
  REDACTION_SALT?: string;

  // ---- Runtime vars (from wrangler.toml [vars]) ------------------------
  WATCHTOWER_ENV: string;
  USER_AGENT: string;

  // Free-tier job bounds
  FREE_TIER_MAX_JOBS_PER_CRON: string;          // scan jobs claimed per cron tick
  FREE_TIER_MAX_NOTIFICATIONS_PER_CRON: string; // notification jobs claimed per tick
  FREE_TIER_SCAN_TIMEOUT_MS: string;            // wall-clock budget per scan job

  // Scan pipeline tuning
  PASSIVE_RESCAN_MINUTES: string;    // how often each target gets re-scanned
  BRUTEFORCE_CHUNK: string;          // subdomain wordlist names resolved per tick
  BRUTEFORCE_CONCURRENCY: string;    // parallel DoH queries during bruteforce
  PROBE_LIMIT_PER_SCAN: string;      // HTTP probes (incl. JS analysis) per tick
  FUZZ_REQUESTS_PER_TICK: string;    // wordlist fuzz requests per host per tick
}

export const num = (v: string | undefined, fallback: number): number => {
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};
