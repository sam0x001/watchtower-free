# Watchtower

![banner](./img/banner.jpg)

A bug-bounty monitoring bot on Cloudflare Workers (**free tier**): it watches
your public bug-bounty targets around the clock and sends a Telegram message
for every **new** finding — new subdomains, live hosts, technologies, JavaScript
files, endpoints, secrets, certificates, CVEs, content changes and
sensitive-path fuzz hits.

> **v4.0.0-free** — breaking change from the 3.x line. The old authorization
> workflow, reports, integrations, REST API, emergency stop, runners and audit
> logs are gone. The D1 schema is incompatible with previous versions — see
> [DEPLOYMENT.md](./DEPLOYMENT.md#recreating-the-d1-database).

## ⚠️ Read this before you run anything

**This is an offensive-security tool.** It sends live HTTP requests to hosts you
name, brute-forces DNS against a wordlist and fuzzes for exposed files and
admin panels. That is reconnaissance against systems you do not own unless you
have explicit, documented permission to test them.

By using it you take responsibility for the following:

- **Only monitor targets you are authorized to test.** Passive bug-bounty
  programs (HackerOne, Bugcrowd, Intigriti, …) and written contracts are the
  normal case. "It is on a CT log" and "it resolves in DNS" are *not*
  authorization — a host being publicly reachable says nothing about whether
  you may touch it.
- **Stay inside the published scope** — and inside the exclusions you configure.
  `/add example.com` means *every* subdomain of that domain is in scope, which
  is frequently wider than the actual program scope. Read the program's rules
  before adding a domain, and `/exclude` anything you must not touch.
- **Respect rate limits and the program rules.** Defaults here are tuned for
  Cloudflare's free tier, not for politeness. If a program forbids active
  scanning, set `passive_only` and leave the active features off.
- **Understand what the tool does not do.** It does not exploit, brute-force
  credentials, or perform denial-of-service, and it never stores a found
  credential value — but it does hit live hosts with real requests.
- **You are responsible for your use.** The maintainer is not liable for
  anything you do with this software, and running it against systems without
  permission may violate the CFAA, the UK Computer Misuse Act, and equivalent
  laws in most jurisdictions — regardless of intent or outcome.

Scope enforcement is default-deny and enforced before every outbound request
(see [SECURITY.md](./SECURITY.md)), but that is a safety net, not permission.
When in doubt, don't add the target.

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
/target_add shop           ← group your program's domains (optional)
/add shop.example.com shop ← filing a domain under the category
/scan shop                 ← scans the whole category; results in chat
every 5 minutes forever    ← only NEW findings are reported from now on
```

- Categories are an **organizational layer only**: they group domains under
  one id so `/target_info` can show them together. Scanning, exclusions and
  feature toggles all operate on the **domain** — never the category.
- `/add example.com` implies `*.example.com` — **every** subdomain is in scope.
  There is no scope declaration step. The category argument is optional;
  domains without one are "standalone" and still fully monitored.
- `/exclude` carves holes: a single subdomain (`sub.example.com`), a wildcard
  (`*.dev.example.com`) or a path (`example.com/excluded`). Excluded assets are
  never requested — the scope check runs before any network call.
- `/scan <category_or_domain>` runs a discovery pass immediately (summary + the
  new-asset alerts in chat). CT logs and DNS records are third-party API calls
  that answer in seconds, so they run inline; live-host probing, JavaScript,
  CVE matching and wordlist fuzzing stay on the cron, where they are chunked to
  fit the free tier — you get a message as each of those lands. Scanning a
  category covers every domain filed under it, five per command.
- The baseline is recorded, so the cron only re-reports genuinely new findings.
- Everything is chunked: passive discovery is fast third-party API calls,
  while the slow phases (subdomain bruteforce, fuzz wordlists) advance a small
  slice per tick and keep their cursor in KV; HTTP probes rotate through
  known hosts (`assets.last_probed`), a few at a time.

## Commands

| Command | What it does |
|---|---|
| `/start` | Welcome screen (also answers before you are allowlisted, so you can see your Telegram ID) |
| `/help` | This list, in chat |
| `/target_add <name>` | Create a target category, e.g. `/target_add shop` |
| `/target_info <name\|id>` | Every domain added under that category, with last scan / exclusions / feature count |
| `/add <domain> [category]` | Start monitoring. Every subdomain is in scope immediately; optional 2nd arg files it under a category |
| `/remove <domain>` | Stop monitoring and delete everything stored for the target |
| `/remove <category>` | Stop a whole category — asks you to confirm with a token first, then deletes the category **and** every domain under it |
| `/list` | Categories with their domains, then standalone domains — plus asset counts, last scan and exclusions |
| `/exclude <domain> <value...>` | Skip a subdomain, `*.wildcard` or `domain/path` from scanning |
| `/exclude list <domain>` | Show a target's exclusions |
| `/exclude remove <domain> <value>` | Un-exclude |
| `/scan <category>` | Scan a whole category now — the CT/DNS discovery pass runs inline for its domains, in batches of 5 |
| `/scan <domain>` | Initial scan now (summary + new-asset alerts in chat), then continuous monitoring |
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

## Secrets and security

**This repository contains no secrets.** All four credentials are placeholders,
set out-of-band at deploy time:

| Secret | Set with | Purpose |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | `wrangler secret put` | bot identity from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_WEBHOOK_SECRET` | `wrangler secret put` | validates inbound `/telegram` (header or `?secret=`) |
| `AUTHORIZED_TELEGRAM_IDS` | `wrangler secret put` | comma-separated bootstrap allowlist; extend with `/allow` |
| `REDACTION_SALT` | `wrangler secret put` | salts secret fingerprints — generate with `openssl rand -hex 32` |

- Never put a secret in `wrangler.toml`, in code, or in a committed file. Use
  `wrangler secret put` (or `.dev.vars`, which is gitignored). Templates live in
  [`.env.example`](./.env.example) and [`.dev.vars.example`](./.dev.vars.example).
- `wrangler.toml` ships with empty `database_id` / `id` / `preview_id`. Fill
  them with your own resource IDs after `wrangler d1 create` — the values
  committed here are never anyone else's.
- `scripts/webhook-tester.sh` reads the bot token from a shell variable; prefer
  `wrangler secret put` over pasting a token into an interactive shell, which
  persists it in shell history.
- Detected secrets are never stored in full — only salted SHA-256 fingerprints
  (`src/lib/redact.ts`). See [SECURITY.md](./SECURITY.md) for the full model and
  [docs/incident-response.md](./docs/incident-response.md) for rotation steps if
  something leaks.

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
- [LICENSE](./LICENSE) — Apache-2.0; no warranty, use at your own risk
- [CHANGELOG.md](./CHANGELOG.md) — what changed across versions
- [docs/architecture.md](./docs/architecture.md) — pipeline internals
- [docs/threat-model.md](./docs/threat-model.md) — threats and mitigations
- [docs/data-retention.md](./docs/data-retention.md) — what is kept and for how long
- [docs/incident-response.md](./docs/incident-response.md) — what to do when something goes wrong

## License

Apache-2.0

