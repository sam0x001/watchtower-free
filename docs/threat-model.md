# Watchtower — Threat Model

## System under consideration

Watchtower is a Cloudflare Workers-based Telegram bot that orchestrates
passive and low-impact security reconnaissance against authorized targets.

## Trust boundaries

1. **Operator ↔ Telegram bot** — Telegram users issuing commands.
2. **Bot ↔ target infrastructure** — outbound HTTP/DNS to authorized targets.
3. **Bot ↔ third-party recon APIs** — crt.sh, Cert Spotter, OSV, etc.
4. **Bot ↔ external scanner runner** — signed job/result payloads.
5. **Bot ↔ notification destinations** — Slack, Jira, GitHub, email, webhooks.
6. **Bot ↔ Cloudflare bindings** — D1, R2, KV, Queues, Durable Objects.

## Assets

- **Target scope** — the authoritative list of allowed/denied hosts.
- **Authorization references** — written permission records.
- **Evidence** — encrypted HTTP responses, screenshots, scanner output.
- **Findings** — vulnerability records with redacted secrets.
- **Audit log** — append-only record of every action.
- **API tokens** — short-lived HMAC-signed REST tokens.

## Adversaries

1. **Malicious operator** — attempts to scan out-of-scope targets.
2. **Compromised Telegram account** — attempts to issue destructive commands.
3. **Compromised external runner** — attempts to forge results.
4. **Compromised third-party recon API** — attempts to inject malicious JSON.
5. **Attacker controlling the target** — attempts SSRF, redirect, DNS rebinding.
6. **Insider with DB read access** — attempts to exfiltrate encrypted evidence.

## Threats and mitigations

| Threat | Vector | Mitigation |
|--------|--------|------------|
| Out-of-scope scanning | Operator adds unauthorized scope | Authorization reference required + broad-wildcard rejection + metadata-IP blocking |
| SSRF to internal services | Bot fetches attacker URL | DoH pre-resolution + private-range blocking + scope check |
| Redirect to attacker host | In-scope target returns 302 to attacker | `validateRedirect()` re-checks destination against scope |
| DNS rebinding | Bot resolves host then fetches — IP changes between | Best-effort: DoH pre-resolution; Cloudflare Workers re-resolves internally. Documented as a residual risk. |
| Command injection | Operator passes shell metacharacters in args | `validateToolArgs()` rejects shell metacharacters + Workers don't shell out at all |
| Forged runner result | Runner posts fake `nmap` output | HMAC-signed result payloads + signature verification |
| Secret leakage via Telegram | Bot sends full token in message | `redactSync()` runs on every Telegram message body |
| Secret leakage via audit log | Operator reads audit table | Logger rejects secret-named fields; redaction runs before INSERT |
| Secret leakage via evidence | Insider with R2 read | AES-GCM at-rest encryption; signed short-lived URLs required |
| Path traversal | Wordlist entry contains `../` | `sanitizeWordlistEntry()` rejects `..` and control chars |
| Zip bomb | Wordlist contains huge nested payload | Per-response size ceiling; entries limited to 256 chars |
| ReDoS | Operator submits malicious regex | No operator-supplied regex anywhere; all patterns are hardcoded |
| Replay attack | Attacker replays old webhook | `exp` claim in signed tokens; replay window capped |
| Credential stuffing | Operator brute-forces API token | Rate-limited via `RateLimiterDO`; tokens are short-lived |
| Denial of service against target | Operator runs aggressive scan | Passive by default; rate limits per target; emergency stop |
| Cross-tenant data leakage | DB query leaks across orgs | All queries org-scoped; multi-tenant isolation enforced |
| Privilege escalation | Viewer role runs admin command | RBAC checks in `api/router.ts` and `telegram/commands.ts` |
| Insecure runner container | Runner has network egress to attacker | `network_egress_allowlist_json` on runner registration |

## Residual risks

- **DNS rebinding** — Cloudflare Workers' fetch re-resolves internally, but
  the DoH pre-check could theoretically diverge from the runtime's view. We
  document this as a residual risk and recommend egress-locked runners for
  high-assurance deployments.
- **Third-party recon API compromise** — if crt.sh or Cert Spotter returns
  malicious JSON, our parser is designed to fail-safe (reject malformed
  JSON rather than treat as asset removal). Operators should still monitor
  provider incident reports.
- **External runner compromise** — a fully compromised runner could execute
  arbitrary code in its sandbox. Mitigations include read-only filesystem,
  network egress allowlist, and short-lived job tokens. A compromised runner
  cannot sign arbitrary results without the Worker's HMAC key (held in
  `API_HMAC_KEY` Cloudflare secret).
