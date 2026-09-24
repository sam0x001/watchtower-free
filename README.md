# Watchtower

A bug-bounty monitoring bot on Cloudflare Workers (**free tier**): it watches
your public bug-bounty targets around the clock and sends a Telegram message
for every **new** finding — new subdomains, live hosts, technologies, JavaScript
files, endpoints, secrets, certificates, CVEs, content changes and
sensitive-path fuzz hits.

> **v4.0.0-free** — breaking change from the 3.x line. The old authorization
> workflow, reports, integrations, REST API, emergency stop, runners and audit
> logs are gone. The D1 schema is incompatible with previous versions — see
> [DEPLOYMENT.md](./DEPLOYMENT.md#recreating-the-d1-database).

## What it does

Four capabilities, nothing else:

1. **Subdomain enumeration** — Certificate Transparency logs (crt.sh,
   crtndstry, CertSpotter) plus live DNS lookups (DNS-over-HTTPS), plus a
   wordlist bruteforce with a wildcard-DNS guard (gibberish-resolving domains
   are wildcarded, and hits resolving only to wildcard IPs are discarded).
2. **Asset discovery (JS)** — live hosts are probed over HTTP/HTTPS, discovered
   `<script>` files are tracked by content hash (a redeploy = an alert), and
   endpoint-like strings are extracted from the JS bodies.
3. **Sensitive-data fuzzing** — the wordlists in `fuzz-wordlists/` (`api.txt`,
   `directories.txt`, `files.txt`, `fuzz.txt`) are replayed against every live
   host, chunked across cron ticks. Interesting responses (`.env` files, config
   dumps, backups, exposed archives, admin panels, new JSON/XML API routes)
   become findings.
4. **Technology fingerprinting + CVE matching** — Server/`X-Powered-By` headers
   and HTML generator tags are fingerprinted (with versions where extractable),
   and versioned technologies are checked against
   [OSV.dev](https://osv.dev). A match is stored once as a finding and reported
   with its CVE id, CVSS score and severity.

## How it works

```
/target-add shop           ← group your program's domains (optional)
/add shop.example.com shop ← filing a domain under the category
/target-info shop          ← every domain added for this category
/scan shop.example.com     ← first results land in chat within seconds
every 5 minutes forever    ← only NEW findings are reported from now on
```

- Categories are an **organizational layer only**: they group domains under
  one id so `/target-info` can show them together. Scanning, exclusions and
  feature toggles all operate on the **domain** — never the category.
- `/add example.com` implies `*.example.com` — **every** subdomain is in scope.
  There is no scope declaration step. The category argument is optional;
  domains without one are "standalone" and still fully monitored.
- `/exclude` carves holes: a single subdomain (`sub.example.com`), a wildcard
  (`*.dev.example.com`) or a path (`example.com/excluded`). Excluded assets are
  never requested — the scope check runs before any network call.
- `/scan <domain>` runs an initial scan immediately (summary + the urgent
  high/critical alerts in chat), then monitoring continues on the 5-minute
  cron. The baseline is recorded, so the cron only re-reports genuinely new
  findings.
- Everything is chunked: passive discovery is fast third-party API calls,
  while the slow phases (subdomain bruteforce, fuzz wordlists) advance a small
  slice per tick and keep their cursor in KV; HTTP probes rotate through
  known hosts (`assets.last_probed`), a few at a time.

## Commands

| Command | What it does |
|---|---|
| `/start` | Welcome screen (also answers before you are allowlisted, so you can see your Telegram ID) |
| `/help` | This list, in chat |
| `/target-add <name>` | Create a target category, e.g. `/target-add shop` |
| `/target-info <name\|id>` | Every domain added under that category, with last scan / exclusions / feature count |
| `/add <domain> [category]` | Start monitoring. Every subdomain is in scope immediately; optional 2nd arg files it under a category |
| `/remove <domain>` | Stop monitoring and delete everything stored for the target |
| `/list` | Categories with their domains, then standalone domains — plus asset counts, last scan and exclusions |
| `/exclude <domain> <value...>` | Skip a subdomain, `*.wildcard` or `domain/path` from scanning |
| `/exclude list <domain>` | Show a target's exclusions |
| `/exclude remove <domain> <value>` | Un-exclude |
| `/scan <domain>` | Initial scan now (summary + urgent alerts in chat), then continuous monitoring |
| `/feature <domain>` | Status board of that target's monitoring features |
| `/feature <domain> <key> <on\|off>` | Toggle one monitoring feature (see below) |
| `/allow <telegram_id>` | Let another Telegram user talk to this bot |
| `/disallow <telegram_id>` | Revoke a user's access (env-seeded IDs must be edited in the env var) |

Anyone who is not on the allowlist (the `AUTHORIZED_TELEGRAM_IDS` env seed
plus `/allow` entries) gets a single reply —
`⛔ Unauthorized. Contact your Watchtower administrator.` — and nothing else.

## Monitoring features (per target)

Every target has eight independent switches, listed with
`/feature <domain>` and toggled with `/feature <domain> <key> <on|off>`:

| key | What it gates |
|---|---|
| `subdomain_enum` | CT logs + DNS records (passive discovery) |
| `dns_brute` | wordlist subdomain bruteforce chunk |
| `js_changes` | JavaScript discovery + hash diff + secret scan |
| `fuzz_files` | common-file fuzz chunk on probed hosts |
| `deep_fuzz` | doubled fuzz slice on freshly discovered hosts (needs `fuzz_files`) |
| `status_watch` | service/tech storage + change alerts (status, titles, servers, redirects) |
| `port_watch` | one extra non-standard port per probed host per tick |
| `nuclei` | template scanning — needs an external runner, OFF by default and refuses `on` |

Everything is on by default except `nuclei`. A disabled phase is skipped
entirely — it costs zero requests and zero CPU. Toggles apply from the next
scan pass (run `/scan <domain>` to see the effect immediately).

## Notifications

Telegram messages go to **every** allowlisted user. Each new finding is
delivered **once** (deduplicated per finding for a week); repeated scans never
re-send what you already saw.

| Kind | Message |
|---|---|
| New subdomain / live host / IP / DNS record | hostname, source, IP |
| New TLS certificate | issuer, serial, validity |
| New technology / version change | host, tech, before → after |
| New / changed JavaScript file | URL, SHA-256 prefix, size |
| New API endpoint | method + path, source JS file |
| Possible secret in JS | type, line, salted fingerprint (the value is **never stored**) |
| CVE match | advisory id, CVSS, fixed version, osv.dev link |
| Service title / status / server change | before → after |
| Sensitive fuzz path | URL, status, classification |
| Scan failed | job id, error |

## Architecture

```
Telegram ──updates──▶ Worker (/telegram) ──commands──▶ D1 (targets, scopes)
                                          └─/scan─────▶ inline scan pass

every 5 min:  cron ──▶ 1. send pending Telegram notifications
                    ──▶ 2. run up to 2 scan jobs
                    ──▶ 3. schedule scans for targets not scanned in 30 min
                    ──▶ 4. (hourly) purge old jobs + notifications

each scan pass: passive CT+DNS → bruteforce chunk → probe rotation
    probes → services/tech → OSV CVE match → JS analysis → fuzz chunk
    findings (stored once per fingerprint) → alerts → notification jobs
```

Storage: **D1** for everything relational (targets, scope/exclusions,
allowed users, locks, assets, scans, findings, job queue, notification log) —
**KV** for wordlist cursors and the wildcard-DNS cache. No R2, no Durable
Objects, no Queues (see `wrangler.toml` for the exact tunables).

## Free-tier notes

- All scanning is **passive and rate-bounded**: ≤16 concurrent DoH lookups,
  2 concurrent fuzz requests with 250 ms gaps, a 40-request fuzz slice per
  host per tick, ≤5 hosts probed per tick, and an immediate stop on HTTP 429.
- Bounded wall-clock budget per scan (default 60 s on cron, 40 s on `/scan`);
  heavy phases resume where they left off on the next tick.
- Targets re-scan at most every 30 minutes (`PASSIVE_RESCAN_MINUTES`), never
  every tick. KV writes are one cursor update per host actually probed.
- Costs stay at $0/month: the exact free-tier footprint is documented in
  [DEPLOYMENT.md](./DEPLOYMENT.md).

## Development

```bash
npm install
npm run typecheck   # must be clean
npm test            # 18 files / 149 tests must pass
```

Wordlists: `fuzz-wordlists/*.txt` are bundled as text modules (see the
`[[rules]]` block in `wrangler.toml` and the `.txt` plugin in
`vitest.config.ts`).

## Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) — fresh deploy, D1 recreate, secrets, webhook
- [SECURITY.md](./SECURITY.md) — access control, SSRF, redaction, responsible use
- [CHANGELOG.md](./CHANGELOG.md) — what changed across versions
- [docs/architecture.md](./docs/architecture.md) — pipeline internals
- [docs/threat-model.md](./docs/threat-model.md) — threats and mitigations
- [docs/data-retention.md](./docs/data-retention.md) — what is kept and for how long
- [docs/incident-response.md](./docs/incident-response.md) — what to do when something goes wrong

## License

Apache-2.0

