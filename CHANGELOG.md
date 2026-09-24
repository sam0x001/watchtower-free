# Changelog

## v4.0.0-free — scope-exclude model, chunked scanning, Telegram-only alerts

Breaking change from the 3.x line:

- Targets are public bug bounty programs: the authorization/target-ownership
  workflow is gone. `/add example.com` implies `*.example.com` — all
  subdomains are in scope. Monitoring ends only with `/remove`.
- Scope is now **exclusion-based**: `/exclude` skips a subdomain, a
  `*.wildcard` or a `domain/path` (denylist; checked before any network call).
- Kept capabilities only: subdomain enumeration (CT + DNS + wordlist
  bruteforce), asset/JS discovery, sensitive-data fuzzing with
  `fuzz-wordlists/`, technology fingerprinting + CVE matching (OSV.dev).
  Reports, integrations, REST API, emergency stop, runners, audit logs and
  evidence storage are removed.
- `/scan <domain>` runs an initial scan inline (summary + high/critical
  alerts in chat); the 5-minute cron keeps watching and reports only new
  findings. Every new asset/change of any kind notifies over Telegram.
- Chunked for the Workers free plan: CT/DNS providers stay fast third-party
  calls; bruteforce + fuzzing advance a bounded slice per tick with KV
  cursors; HTTP probes rotate via `assets.last_probed`; per-target D1 locks.
- Wildcard-DNS false-positive guard: gibberish-resolving domains are treated
  as wildcarded; bruteforce hits resolving only to wildcard IPs are dropped.
- Schema incompatible with 3.x: separate migration files (`0001_core` …
  `0006_target_groups`); the deployment guide tells you to recreate the
  D1 database.
- **Target categories**: `/target_add <name>` creates a category,
  `/add <domain> <category>` files a domain under it, and
  `/target_info <category>` lists every member with last scan, exclusions and
  its feature count. Categories only organize domains — scanning, exclusions
  and **feature toggles stay strictly per domain**. Deleting a category
  detaches (never deletes) its domains.
- Docs rewritten for v4: README, DEPLOYMENT, SECURITY, CHANGELOG,
  `docs/architecture.md`, `docs/threat-model.md`, `docs/data-retention.md`,
  `docs/incident-response.md`, `fuzz-wordlists/README.md`. Removed
  `docs/openapi.yaml` (the REST API no longer exists) and root scratch files
  (`d1-*.txt`, `jq-*.txt`, `tmp-*`, `prompt.txt`); `.gitignore` entries for
  them dropped accordingly. The conflicted `fuzz-wordlists/subdomains.txt`
  working-copy edit was backed up to the system temp dir and restored to the
  committed 54-entry list.
- Also fixed along the way: IPv4-mapped IPv6 parsing, unsigned-range SSRF
  filtering (192.168/16, 169.254/16, 172.16/12, multicast…), per-label domain
  validation, Google API key / PEM-block redaction, cyclic-structure depth
  guard, and distinct `no_scope` / `blocked_ip_range` scope reasons.

## v3.0.0-free — runs on Cloudflare Workers FREE tier

### The change

Removed all dependencies on Cloudflare paid features (Queues + Durable Objects).
The bot now runs entirely on the free plan — $0/month.

### What was replaced

| Paid feature | Free-tier replacement | File |
|---|---|---|
| Cloudflare Queues (3 of them: scan, notify, report) | `job_queue` D1 table polled by the single cron trigger every 5 min | `src/db/job-queue.ts` |
| `EmergencyStopDO` Durable Object | `emergency_stop_state` D1 table (single row per scope+id) | `src/db/emergency-stop.ts` |
| `RateLimiterDO` Durable Object | `rate_limits_v2` D1 table (sliding-window hits + backoff_until) | `src/db/rate-limiter.ts` |
| `LockDO` Durable Object | `locks` D1 table with `locked_until` + `INSERT ... ON CONFLICT DO NOTHING` | `src/db/distributed-lock.ts` |
| `JobCoordinatorDO` Durable Object | `JobCoordinatorClient` that does `SELECT COUNT(*) FROM job_queue` | `src/db/job-coordinator.ts` |
| 5 Cron Triggers | 1 Cron Trigger (`*/5 * * * *`) with internal time-of-day dispatch | `src/cron/handler.ts` |

### Files changed

- `src/db/job-queue.ts` — NEW. D1-backed queue with `enqueueJob`, `claimPendingJobs`, `completeJob`, `failJob`, `cancelJob`, `purgeOldJobs`. Dedup via `dedup_key`.
- `src/db/emergency-stop.ts` — NEW. D1-backed emergency stop with auto-expiry. Drop-in `EmergencyStopClient` compatibility shim.
- `src/db/rate-limiter.ts` — NEW. D1-backed sliding-window rate limiter with circuit-breaker behavior.
- `src/db/distributed-lock.ts` — NEW. D1-backed lock with atomic `INSERT ... ON CONFLICT DO NOTHING` acquisition + auto-expiry.
- `src/db/job-coordinator.ts` — NEW. Counts active jobs per target via D1 query.
- `src/queues/scan-runner.ts` — REPLACES `scan-consumer.ts`. Reads pending scan jobs from `job_queue`, runs them, enqueues alerts as notification jobs.
- `src/queues/notification-dispatcher.ts` — REPLACES `notification-consumer.ts`. Reads pending notification jobs from `job_queue`, sends them via the configured channel.
- `src/cron/handler.ts` — REWRITTEN. Single cron handler that dispatches scans + notifications + scheduled scans + scope-expiry warnings + retention purge.
- `src/index.ts` — REWRITTEN. Removed `queue()` handler + DO class exports. Only `fetch` + `scheduled` remain.
- `src/env.ts` — REWRITTEN. Removed `SCAN_QUEUE`/`NOTIFY_QUEUE`/`REPORT_QUEUE` + 4 DO namespace types. Added `FREE_TIER_MAX_CPU_MS`/`FREE_TIER_MAX_JOBS_PER_CRON`/`FREE_TIER_SCAN_TIMEOUT_MS`.
- `src/telegram/commands.ts` — UPDATED. `/scan_passive`, `/scan_cancel`, `/report_create`, `/stop`, `/resume` all use the new D1-based helpers.
- `wrangler.toml` — REWRITTEN. Removed `[[queues.producers]]`, `[[queues.consumers]]`, `[[durable_objects.bindings]]`, `[[migrations]]`. Reduced limits for free tier. Single `[triggers]` cron.
- `migrations/0010_free_tier_job_queue.sql` — NEW. Creates `job_queue`, `emergency_stop_state`, `rate_limits_v2`, `locks` tables.
- `test/job-queue.test.ts` — NEW. Tests enqueue/claim/complete/fail/cancel/dedup/purge.
- `test/emergency-stop.test.ts` — REWRITTEN. Tests the D1-backed version.
- `test/rate-limit.test.ts` — REWRITTEN. Tests the D1-backed version.

### Removed (no longer needed)

- `src/do/emergency-stop.ts` — replaced by `src/db/emergency-stop.ts`
- `src/do/lock.ts` — replaced by `src/db/distributed-lock.ts`
- `src/do/rate-limiter.ts` — replaced by `src/db/rate-limiter.ts`
- `src/do/job-coordinator.ts` — replaced by `src/db/job-coordinator.ts`
- `src/queues/scan-consumer.ts` — replaced by `src/queues/scan-runner.ts`
- `src/queues/notification-consumer.ts` — replaced by `src/queues/notification-dispatcher.ts`

### Free-tier constraints respected

| Free-tier limit | How we respect it |
|---|---|
| 100k Worker requests/day | Cron fires 288 times/day (every 5 min) + Telegram webhook — well under 100k |
| 10ms CPU per invocation | Scan work runs in `ctx.waitUntil()` which has a 30s wall-clock budget; CPU time per request stays under 10ms because providers are I/O-bound |
| 1 Cron Trigger | Single `*/5 * * * *` cron with internal time-of-day dispatch for hourly/daily jobs |
| D1: 5M reads / 100k writes per day | Each cron tick does ~10-50 D1 reads + 5-20 writes. ~14k writes/day max — well under limit |
| D1: 5 GB storage | `purgeOldJobs()` deletes old completed/failed rows every hour; retention windows shortened (audit 90d, evidence 90d, JS 30d) |
| R2: 10 GB / 1M+10M ops/month | Evidence capped at 90d retention + 1 MiB max response size |
| KV: 100k reads / 1k writes per day | Used only for provider response caching (5-min TTL) |

### Latency comparison

| | v2.1.0 (paid) | v3.0.0-free |
|---|---|---|
| Cron cadence | 5 min | 5 min |
| Scan → alert enqueued | ~5-30s (queue) | ~5-30s (D1 job) |
| Alert enqueued → Telegram delivered | ~1-5s (queue consumer) | ~5 min (next cron tick) |
| **Total: change → Telegram alert** | **~5-10 min** | **~10-15 min** |

The free-tier version is ~5 min slower per alert because the notification
job has to wait for the next cron tick to be dispatched (instead of being
picked up immediately by a queue consumer). For a security monitoring bot,
5 extra minutes of latency is acceptable in exchange for $0/month.

## v2.1.0 — automatic alerting wired end-to-end

### The change you asked for

Watchtower now actually **tells you** when something changes on a target. The
scan consumer collects `Alert` objects for every new/changed asset type and
enqueues each one to `NOTIFY_QUEUE`, which delivers a Telegram message within
~5–10 minutes of the change happening on the target.

### Files changed

- `src/db/queries/assets.ts` — every upsert now returns `{ id, created }`
  (and `previous_sha` for JS files). New: `upsertService()` returns a `changes`
  array listing every field that differs from the previous probe. New:
  `upsertTechnology()` returns `versionChanged` + `previousVersion` for
  version-upgrade detection.
- `src/modules/alerts.ts` — new file. Defines the unified `Alert` type,
  `severityFor()` mapping, and `buildAlert()` helper that produces a
  deterministic `dedup_key` of the form `<type>:<target_id>:<asset_value>`.
- `src/modules/asset-discovery.ts` — rewritten to return `Alert[]` instead of
  bare counts. Each new subdomain, new IP, new certificate, and new DNS
  record generates a corresponding alert.
- `src/modules/js-analyzer.ts` — rewritten to return `Alert[]` for new JS
  files, changed JS files, new API endpoints, and detected secret candidates.
  The full secret value is never placed on an alert — only the salted
  fingerprint and a redacted preview.
- `src/queues/scan-consumer.ts` — completely rewritten pipeline:
  1. Run CT + DNS discovery → collects alerts for new subdomains / IPs / certs / DNS records.
  2. For each in-scope subdomain, run HTTP probe → collects alerts for new services / technologies / title changes / status changes / header changes.
  3. For each in-scope HTTP asset, run JS analyzer → collects alerts for new/changed JS, new endpoints, secrets.
  4. Enqueue every collected alert to `NOTIFY_QUEUE` with a deterministic `dedup_key`.
  5. On scan failure, enqueue a `scan_failed` alert so the operator knows.
- `src/queues/notification-consumer.ts` — improved Telegram formatter that
  renders target name, change type, finding ID, and severity-coded emoji.
- `test/alerts.test.ts` — new test suite covering severity mapping, dedup-key
  stability, alert-type coverage.

### Alert types now wired

| Type | Severity | When |
|---|---|---|
| `new_subdomain` | medium | CT provider returns a hostname not previously seen |
| `new_ip` | medium | DNS resolution returns a new IP |
| `new_certificate` | high | New TLS certificate serial observed |
| `new_dns_record` | low | New A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV/HTTPS record |
| `new_service` | medium | First successful HTTP response from an in-scope host |
| `new_technology` | low | New tech fingerprinted on an HTTP asset |
| `technology_version_changed` | medium | Tech version changed |
| `service_title_changed` | low | HTML `<title>` changed |
| `service_status_changed` | medium | HTTP status code changed |
| `service_header_changed` | low | `Server` header changed |
| `new_javascript_file` | medium | New `<script src>` discovered |
| `javascript_changed` | low | JS file SHA-256 changed (deployment) |
| `new_api_endpoint` | medium | New endpoint-like path extracted from JS |
| `new_secret_candidate` | high | High-confidence secret pattern detected |
| `scan_failed` | high | Scan threw an error |

### Known limitation: removed assets

Removed subdomains / JS files / DNS records are NOT currently alerted.
Detecting removals safely requires the provider to explicitly return an empty
result (so we can distinguish "asset gone" from "provider outage"). This is
documented in the README as a known limitation.

## v2.0.0 — incremental migrations + hardened foundation

### Changed (vs v1.0.0)

**Migrations split into incremental files** (the main request):

- `0001_initial.sql` — organizations, users, roles, memberships, api_tokens, targets, scopes, scope_rules, audit_logs
- `0002_assets.sql` — assets, dns_records, certificates, services, technologies
- `0003_javascript_api.sql` — javascript_files, javascript_diffs, api_endpoints, source_maps
- `0004_scans_findings.sql` — scans, scan_jobs, scan_results, findings, finding_evidence, finding_comments, finding_history
- `0005_changes_notify.sql` — changes, notifications, alert_rules
- `0006_runners.sql` — runners, runner_jobs, runner_heartbeats
- `0007_wordlists_reports.sql` — wordlists, wordlist_entries, reports
- `0008_seed.sql` — default roles + capabilities
- `0009_provider_defaults.sql` — provider adapter config
- `seed_authorized_example.sql` — example target bootstrap

This means the next time you need to add a column you add `0010_xxx.sql`
instead of editing the init — `wrangler d1 migrations apply` will track
each file independently in `d1_migrations`.

### Hardened foundation (merged from watchtower1)

- **Scope engine** (`src/scope/match.ts`, 928 lines) — fail-closed by design,
  with control-proof host detection (`_acme-challenge.`, `_dmarc.`),
  reserved documentation domain blocking (RFC 2606), port/path/method/scheme
  rule engine, state-changing method gating (POST/PUT/PATCH/DELETE require
  explicit allow rule + human approval), explicit IPv6 ULA + multicast +
  link-local + NAT64 + 6to4 blocking
- **Salted secret fingerprints** (`src/lib/redact.ts`) — the v1 design was
  unsalted, so a leaked fingerprint could be brute-forced offline. The new
  `fingerprintSecret()` mixes in `REDACTION_SALT` (a Worker secret), making
  each deployment's fingerprints independent
- **Typed error taxonomy** (`src/lib/errors.ts`) — 30+ error codes
  (`scope_missing`, `scope_expired`, `out_of_scope`, `ssrf_blocked`,
  `redirect_blocked`, `dns_rebinding_detected`, `approval_required`,
  `emergency_stop`, `signature_invalid`, `replay_detected`, etc.) with
  HTTP status mapping and `retryable` classification
- **Structured JSON logger** (`src/lib/logger.ts`) — depth-bounded, length-
  bounded, always runs redaction pass before emit
- **`redactHeaders()`** — dedicated header redaction that handles
  `Headers` objects, plain objects, and array-of-pairs
- **`loadScopeSnapshot()`** — fail-closed D1 loader: unknown scope types,
  unknown rule kinds, and unreadable rows authorize nothing
- **4 Durable Objects** instead of 3: `ScopeLock`, `RateLimiter`,
  `JobCoordinator` (new — enforces `MAX_JOBS_PER_TARGET`), `EmergencyStop`
- **Separate `REPORTS` R2 bucket** in addition to `EVIDENCE`
- **3 queues** instead of 2: `SCAN_QUEUE`, `NOTIFY_QUEUE`, `REPORT_QUEUE`
- **`REDACTION_SALT`** secret added to env template
- **SQLite-backed DOs** (`new_sqlite_classes`) — durable, transactional storage

### Compatibility shims

To avoid rewriting every callsite, the legacy API surface is preserved via
shim modules:

- `src/security/scope.ts` → re-exports `compileScope`, `checkHostInScope`,
  `checkUrlInScope`, `isScopeExpired`, `scopeExpiringSoon` from
  `src/scope/index.ts`
- `src/security/redaction.ts` → wraps `src/lib/redact.ts` and re-exposes
  `detectSecrets`, `redactSync`, `redactWithFingerprints`,
  `containsLikelySecret`, `redactValue`
- `src/audit/logger.ts` → keeps `makeConsoleLogger` + `ConsoleLogger` +
  `D1AuditLogger` interface; modules can keep importing from the old path

Existing modules (telegram, api, providers, do, queues, cron, modules,
notifications, evidence, audit) compile unchanged against these shims.

## v1.0.0 — initial release

See git history. Single-file `0001_init.sql`, simpler scope engine,
unsalted secret fingerprints.
