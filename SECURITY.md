# Watchtower — Security Documentation

## Security model

Watchtower enforces a defense-in-depth security model built around explicit
authorization, scope validation, and human-in-the-loop controls.

### Authorization boundaries

1. **Telegram allowlist** — `AUTHORIZED_TELEGRAM_IDS` env var restricts which
   Telegram users can issue commands during bootstrap.
2. **Per-target authorization reference** — every target must record a
   written contract reference (`authorization_reference` column) before any
   scan can be enqueued.
3. **Per-target scope entries** — every host, IP, CIDR, URL, or API path
   being monitored must match an included scope entry and must NOT match a
   denied scope entry. Scope checks run before every HTTP fetch.
4. **Per-target rate limits** — `max_request_rate_per_min` enforced via the
   `RateLimiterDO` Durable Object.
5. **Per-target concurrency limits** — `max_concurrent_jobs` enforced via
   the `LockDO` Durable Object.
6. **Authorization expiry** — scans are blocked automatically when the
   target's authorization expires. Warning alerts are sent N days before.
7. **Emergency stop** — global, per-organization, per-target, and per-job
   emergency stop is available via `/stop` and the REST API.

### SSRF protection

Outbound HTTP requests go through `safeFetch()`, which:

1. Validates the URL scheme (`http:` or `https:` only).
2. Validates the URL is in scope via `checkUrlInScope()`.
3. Resolves the hostname via DNS-over-HTTPS.
4. Rejects the request if any resolved IP is in a private, loopback,
   link-local, multicast, reserved, or cloud-metadata range.
5. Strips `Authorization` and `Cookie` headers from outbound requests.
6. Limits response size via streaming + early abort.
7. Enforces a per-request timeout via `AbortController`.

Cloudflare Workers' own runtime also blocks private IPs at the network layer;
the DoH pre-check is defense-in-depth.

### Secret redaction

Secret detection runs on every text buffer before storage or notification.
The redaction module detects:

- AWS / GCP / Azure / GitHub / GitLab / Slack / Stripe / Google / Twilio / SendGrid / Mailgun credentials
- JWTs
- Private keys (RSA, EC, OpenSSH, PGP, generic)
- Connection strings (MongoDB, PostgreSQL, MySQL)
- Bearer tokens in `Authorization` headers
- Passwords in URLs and assignment statements
- Webhook URLs containing secrets
- OAuth client secrets

Detected values are **never** stored in plaintext. Only a deterministic
SHA-256 fingerprint is persisted for deduplication. The original encrypted
value may be stored in R2 (AES-GCM) for forensic evidence, accessible only
via short-lived HMAC-signed URLs.

### Audit logging

Every command, scan, finding mutation, evidence access, integration change,
and emergency-stop action is recorded in the `audit_logs` table with:

- user ID and Telegram ID
- organization ID
- action name
- target ID, scope ID, job ID
- scanner name
- **redacted** arguments (secrets auto-stripped)
- result (`success` | `failure` | `blocked` | `denied`)
- error message
- request ID
- timestamp

The audit logger additionally rejects any field whose name suggests a secret
(`password`, `token`, `cookie`, `authorization`, `api_key`, etc.) and
substitutes `<redacted>`.

### Webhook signature verification

All incoming webhooks (Slack, Jira, GitHub, generic) MUST carry an
`x-watchtower-signature` header with an HMAC-SHA256 of the body. Signatures
are compared in constant time.

### Encrypted evidence

Evidence stored in R2 is AES-GCM encrypted using `ENCRYPTION_KEY` (32 bytes).
Object metadata includes the evidence hash for integrity verification on
retrieval. Access is logged with timestamp and access count.

### Cloudflare-specific limits

- Workers cannot execute native binaries — all heavy scanning is delegated
  to external runners via signed job payloads.
- Workers have CPU and execution time limits — long work is moved to queues.
- All HTTP responses are bounded to `MAX_RESPONSE_BYTES` (5 MiB ceiling).
- Certificate-transparency responses are bounded to
  `MAX_CERT_PROVIDER_RESPONSE_BYTES` (25 MiB ceiling).
- JS files are bounded to `MAX_JS_FILE_BYTES` (2 MiB).
- Concurrency is bounded at the provider level (5 simultaneous providers)
  and the per-target level (`max_concurrent_jobs`).
