# Watchtower — Architecture

## High-level design

One Cloudflare Worker, two entry points (`fetch`, `scheduled`), two bindings
(D1 + KV). No Queues, no Durable Objects, no R2, no REST API.

```
                       ┌──────────────────┐
                       │   Telegram API   │
                       └────────┬─────────┘
                                │ HTTPS webhook (secret-token verified)
                                ▼
        ┌───────────────────────────────────────────────────┐
        │                Cloudflare Worker                  │
        │                                                   │
        │  fetch ──┬─ /telegram → allowlist → commands      │
        │          ├─ / , /health → static JSON             │
        │          └─ * → 404                               │
        │                                                   │
        │  scheduled (every 5 min) ─► cron/handler.ts       │
        │      1. send pending Telegram notifications       │
        │      2. run ≤2 scan jobs (D1 job_queue)           │
        │      3. enqueue scans for targets older than      │
        │         PASSIVE_RESCAN_MINUTES                    │
        │      4. hourly: purge old jobs + notifications    │
        └───────────────────────────────────────────────────┘
                                │
              D1 (targets, scopes, assets, scans,
                  findings, job_queue, notifications,
                  target_features, locks)   KV (cursors,
                                             wildcard cache)
```

## Scan pass (`runScanForTarget`)

One bounded pass per target per invocation, gated by the per-domain feature
map and a wall-clock deadline:

```
load target + scopes ─► compileScope (default-deny)
        │
        ▼
per-target D1 lock (locks table) ── busy? → retry next tick
        │
        ▼
① passive discovery        [subdomain_enum]
   crt.sh / crtndstry / certspotter + DoH DNS records
   → assets, certs, dns_records + alerts
        │
        ▼
② bruteforce chunk         [dns_brute]
   BRUTEFORCE_CHUNK names × BRUTEFORCE_CONCURRENCY DoH lookups
   wildcard-DNS guard → KV cursor bf:<targetId>
        │
        ▼
③ probe rotation (≤ PROBE_LIMIT_PER_SCAN per pass)
   ORDER BY last_probed IS NULL DESC, last_probed ASC
   per host:
     checkHostInScope() FIRST (exclusions cost zero requests)
     https probe, else http probe
     service row + change alerts       [status_watch]
     technologies + version change     [status_watch]
     OSV CVE match per versioned tech  [status_watch]
     JS discovery/hash/secrets         [js_changes]
     fuzz chunk                        [fuzz_files] (+[deep_fuzz] on fresh hosts)
     one rotated extra port            [port_watch]
     set assets.last_probed = now
        │
        ▼
return { alerts, stats } ─► caller decides delivery
```

- **Cron path**: alerts → `notification` jobs (dedup_key) → dispatched on a
  later tick to every allowlisted chat.
- **`/scan` path** (inline): one summary + up to 8 high/critical alerts
  immediately; **every** alert's dedup key is recorded as `sent` so the cron
  never re-sends the baseline.

## Job queue and locks

- `job_queue` (D1): `scan` and `notification` kinds, priority + `dedup_key`,
  attempts with backoff, `locked_until` for claim windows; stale claims are
  auto-expired by the cron.
- `locks` (D1): one row per target key with `locked_until` (ms epoch),
  acquired via `INSERT … ON CONFLICT DO NOTHING`; expired locks can be stolen,
  so a crashed pass never wedges a target.

## Provider pattern

CT/DNS/HTTP sources implement `ReconProvider` (`src/providers/types.ts`) and
are composed by `buildRegistry()`; `runProviders()` caps concurrency at 5.
A provider error is recorded as an error, **never** treated as an asset
removal — only successful responses update the baseline.

## Memory & size ceilings

- HTTP responses: `LIMITS.MAX_RESPONSE_BYTES` (5 MiB) via streaming abort
- CT provider responses: 25 MiB; JS files: 2 MiB each, ≤50 per target
- Fuzz/bruteforce work is chunked; cursors live in KV, state in D1

## Data model (4 migration files + 2)

`0001_core` targets / scopes(+denylist) / allowed_users / locks ·
`0002_assets` assets / dns / certs / services / technologies / js / api ·
`0003_scans_findings` scans / job_queue / findings ·
`0004_notifications` notifications · `0005_target_features` per-domain
toggles · `0006_target_groups` categories (`/target_add`, `/target_info`).

Categories are organizational only: scanning, exclusions and feature toggles
always resolve to a **domain** row.
