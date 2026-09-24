# Watchtower — Security Documentation

## Security model

Watchtower is a **single-operator** bug-bounty monitoring bot: a small
allowlist of Telegram users drives it, it watches public bug-bounty targets,
and every outbound request is filtered through a default-deny scope engine
before a single packet leaves the Worker.

### Access control

1. **Webhook secret** — `/telegram` requests must carry
   `TELEGRAM_WEBHOOK_SECRET` (Telegram's `X-Telegram-Bot-Api-Secret-Token`
   header or a `?secret=` parameter), otherwise the request is rejected with
   401 before the body is parsed.
2. **Telegram allowlist** — every command except `/start` requires the sender's
   id in `AUTHORIZED_TELEGRAM_IDS` (env) ∪ `allowed_users` (D1, managed with
   `/allow` and `/disallow`). Anyone else gets exactly one reply:
   `⛔ Unauthorized. Contact your Watchtower administrator.`
3. **No anonymous surface** — there is no REST API, no unauthenticated route
   besides `/` and `/health` (which return static JSON only).

### Scope enforcement (default deny)

The scope engine (`src/scope/match.ts`) is the only gate between "the operator
typed a name" and "we touch a host":

- **Default deny** — nothing is allowed unless an allowlist row matches.
  `/add example.com` writes the root `domain` row, which covers **every**
  subdomain (no separate scope declaration).
- **Deny beats allow** — `/exclude` rows (subdomain, `*.wildcard`, path) win
  over any allowlist match, and `checkHostInScope()` / `checkUrlInScope()`
  run **before every network request**: probes, JS fetches, fuzz requests,
  bruteforce lookups, and the extra-port rotation all consult it first.
- **Hard-blocked regardless of scope** — private/loopback/link-local/multicast
  ranges, IPv4-mapped equivalents, cloud metadata endpoints
  (`169.254.169.254`, `metadata.google.internal`, …), reserved documentation
  domains (`example.com`, `.test`, `.invalid`, …), and over-broad wildcards
  (`*`, `*.com`).
- **Redirects are re-validated** — a 30x target must pass
  `checkUrlInScope()` again (`validateRedirect()`), so an in-scope host cannot
  bounce us to a third party.
- **No authorization workflow** — v4 targets are public bug-bounty programs by
  design; monitoring runs until `/remove`. The operator is responsible for
  only adding programs they are authorized to test (see Responsible use).

### SSRF protection

Outbound HTTP goes through `safeFetch()` (`src/security/ssrf.ts`):

1. Scheme allowlist (`http:`/`https:` only) and in-scope URL check.
2. Hostname resolved via DNS-over-HTTPS **before** the fetch; the request is
   refused if any resolved IP is private/reserved/metadata (range masks are
   compared unsigned, so e.g. `192.168/16` and `169.254/16` match correctly;
   IPv4-mapped IPv6 like `::ffff:10.0.0.5` is unmapped and checked as IPv4).
3. `Authorization` and `Cookie` headers are stripped from outbound requests.
4. Response size is capped by streaming with an early abort
   (`LIMITS.MAX_RESPONSE_BYTES`), plus a per-request timeout.
5. The fuzzer stops the whole host chunk on HTTP 429 (`stopOn429`), and
   Cloudflare's own runtime blocks private egress as defense-in-depth.

### Secret redaction

- Detected secrets are **never stored in plaintext** — only salted SHA-256
  fingerprints (salt = `REDACTION_SALT`) for deduplication.
- `redactSync()` scrubs notification payloads before they are written to the
  `notifications` table; Telegram messages escape all interpolated strings as
  HTML.
- Pattern coverage: AWS/GCP/Azure/GitHub/GitLab/Slack/Stripe/Google/Twilio/
  SendGrid/Mailgun/OpenAI/npm credentials, JWTs, bearer tokens, connection
  strings, webhook URLs, and **whole PEM private-key blocks** (the entire
  block is replaced, not just the header line).

### Abuse prevention / responsible use

- Requests are GET/HEAD only; no exploitation, no credential testing, no
  form submissions, no state-changing verbs.
- Bounded everything: chunked wordlists, probe rotation, wall-clock deadline
  per pass, `stopOn429`, per-target D1 locks — scanning stays polite and
  inside the Workers free tier.
- The bot never executes shell commands, never runs operator-supplied regex,
  and never touches an excluded host.

### Removed in v4 (no longer attack surface)

REST API + bearer tokens, HMAC webhook signatures, external scanner runners,
Slack/Jira/GitHub/email integrations, encrypted evidence (R2), audit logs,
emergency stop, RBAC/multi-tenancy, and per-target authorization records.

### Reporting a vulnerability

Open a private report through the program the repository is published under,
or contact the maintainer directly. Please include reproduction steps and
impact; do not file public issues for security bugs.
