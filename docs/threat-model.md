# Watchtower — Threat Model

## System

A single-tenant, allowlisted Telegram bot on Cloudflare Workers free tier
that passively monitors public bug-bounty programs (CT logs, DNS, HTTP
probes, JS analysis, wordlist fuzzing, OSV CVE lookups).

## Trust boundaries

1. **Operator ↔ Telegram** — commands arrive via webhook; Telegram is trusted
   for identity, gated by the webhook secret token + allowlist.
2. **Bot ↔ target infrastructure** — outbound HTTP(S)/DoH to in-scope hosts.
3. **Bot ↔ third-party recon APIs** — crt.sh, certspotter, crtndstry,
   cloudflare-dns, api.osv.dev.
4. **Bot ↔ Cloudflare bindings** — D1 (state) and KV (cursors/cache).

There are no other integrations in v4 (no REST API, runners, or chat
integrations).

## Assets

- **Scope rules** (`scopes`) — the allow/deny truth for every request.
- **Allowlist** (`allowed_users` + env) — who may command the bot.
- **Findings** — secrets are salted fingerprints only, never values.
- **Notification log** — redacted bodies, 30-day retention.
- **Targets/features** — monitoring configuration per domain.

## Adversaries

1. **Unallowlisted Telegram user** — tries commands.
2. **Compromised allowlisted account** — full command power (single tier).
3. **Attacker controlling a probed host** — redirects, DNS rebinding,
   malicious JS/HTML responses.
4. **Malicious/compromised recon API** — poisoned JSON.
5. **Insider with D1 read** — sees findings and notification bodies.
6. **The target itself is hostile by default** — it does not want to be
   scanned; we must stay polite and in-scope.

## Threats and mitigations

| Threat | Vector | Mitigation |
|---|---|---|
| Unauthorized commands | Random user messages the bot | Webhook secret token (401) + allowlist gate; `/start` only echoes the caller's id |
| Scanning out of scope | Typo or missing exclusion | Default-deny engine; root `/add` implies `*.domain`; `/exclude` checked before **every** request; reserved doc-domains and metadata IPs hard-blocked |
| Open-redirect escape | In-scope host 30x to third party | `validateRedirect()` re-validates the destination against scope; hops capped |
| SSRF to internal services | Hostname resolves to private IP | DoH pre-resolution + unsigned-mask range checks (192.168/16, 169.254/16, 172.16/12, CGNAT, multicast…) + IPv4-mapped IPv6 unmapping; Cloudflare blocks private egress anyway |
| DNS rebinding | IP changes between check and fetch | Residual risk (documented): DoH pre-check + Workers' own resolver; no IP pinning available |
| Secret leakage in chat | Alert contains a found credential | Values are never stored — fingerprint only; `redactSync()` on notification payloads; HTML-escaping of all interpolated text |
| Secret leakage in DB | Insider reads `notifications`/`findings` | Redacted bodies + salted fingerprints (`REDACTION_SALT`) |
| Wildcard-DNS noise | Wildcard domain makes bruteforce return everything | Nonce-label probe → wildcard IP set (KV, 7d) → hits resolving only to wildcard IPs dropped |
| Resource exhaustion of the Worker | Huge wordlist/response | Byte ceilings (5 MiB HTTP / 25 MiB CT / 2 MiB JS), chunked work, wall-clock deadline per pass, bounded concurrency |
| DoS against the target | Fuzz/bruteforce volume | `BRUTEFORCE_CHUNK`, `PROBE_LIMIT_PER_SCAN`, `FUZZ_REQUESTS_PER_TICK`, 250 ms delay, ≤2 concurrent, stop-on-429 |
| Duplicate alert flood | Repeated scans finding the same thing | Findings deduped per fingerprint forever; alerts deduped 7 days via `notifications.dedupe_key` |
| Concurrent scan clashes | Two cron ticks / `/scan` + cron | Per-target D1 lock with TTL + expired-lock steal; scan job dedup keys |
| Stuck jobs after a crash | Worker died mid-job | Cron auto-expires `running` rows whose `locked_until` passed; retry with backoff → dead_letter |
| Wordlist injection | Malicious entries | Bundled lists only (no operator uploads); `sanitizeWordlistEntry()` rejects traversal/control chars/out-of-charset |
| ReDoS | Operator-supplied pattern | No operator-supplied regex anywhere; all patterns hardcoded |
| Path traversal in fuzzing | `../` in a path | Sanitizer rejects `..` before any request |
| Malicious CT/DNS JSON | Third-party response | Fail-safe parsing: malformed responses are errors, never asset removals |

## Residual risks

- **DNS rebinding** between the DoH pre-check and the runtime fetch (above).
- **Third-party recon APIs** returning poisoned-but-valid JSON — parsers fail
  safe (no removals), but a fake subdomain name could be recorded as an asset
  (it would still pass scope before being probed).
- **Compromised allowlisted account** — one-tier access means full command
  power including `/remove`; mitigate with a dedicated Telegram account and
  `AUTHORIZED_TELEGRAM_IDS` containing only your id.
- **Fuzzing generates traffic** — even politely paced, `fuzz_files` sends real
  GETs to a target; keep it off (`/feature <domain> fuzz_files off`) for
  programs that prohibit content discovery.
