# Watchtower — Free-Tier Deployment Guide
This guide deploys Watchtower v4 on Cloudflare's **free tier only** — no
payment method required, $0/month. The Worker uses D1 (relational state), KV
(cursors + wildcard-DNS cache) and a single cron trigger. There is no R2, no
Queues, no Durable Objects.

## ⚠️ Upgrading from 3.x: recreate the D1 database

v4's schema is **incompatible** with the previous database (different tables
and columns). An old database will not work with the new code.

### Recreating the D1 database

```bash
# 1. Delete the old database
npx wrangler d1 delete watchtower-db

# 2. Create a fresh one and note the new database_id
npx wrangler d1 create watchtower-db

# 3. Put the new database_id in wrangler.toml ([[d1_databases]] → database_id)

# 4. Apply the 6 separate migration files, then verify
npx wrangler d1 migrations apply watchtower-db --remote
```

Expected tables after the migration: `targets`, `scopes`, `allowed_users`,
`locks` (0001), `assets`, `dns_records`, `certificates`, `services`,
`technologies`, `javascript_files`, `api_endpoints` (0002), `scans`,
`job_queue`, `findings` (0003), `notifications` (0004), `target_features`
(0005), `target_groups` + `targets.group_id` (0006).

Migrations stay as **separate files on purpose** (`migrations/0001_core.sql`
through `migrations/0006_target_groups.sql`) so a failure in one area can be
diagnosed and re-applied independently. Check them with:

```bash
npx wrangler d1 migrations list watchtower-db --remote
```

## Prerequisites

- Node.js 20+ (see `.nvmrc`)
- Wrangler CLI (`npm install -g wrangler` or `npx wrangler`)
- A Cloudflare account (free plan, no payment method needed)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

## Step 1 — Install dependencies

```bash
npm install
```

## Step 2 — Provision Cloudflare resources (FREE TIER)

For a first install:

```bash
# D1 database (targets, assets, scans, findings, job queue, notifications)
npx wrangler d1 create watchtower-db
# → copy the database_id into wrangler.toml

# KV namespace (wordlist cursors + wildcard-DNS cache)
npx wrangler kv:namespace create CACHE
# → copy the id (and preview_id for local dev) into wrangler.toml
```

**Do NOT run** `wrangler queues create ...`, do not add R2 buckets, and do not
add Durable Objects — Watchtower v4 needs none of them.

## Step 3 — Set the 4 secrets

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN        # from @BotFather
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET   # any long random string
npx wrangler secret put AUTHORIZED_TELEGRAM_IDS   # your Telegram user id (comma-separated if several)
npx wrangler secret put REDACTION_SALT            # any long random string (salts secret fingerprints)
```

- Never commit secrets. A `.env.example` template exists for reference.
- `AUTHORIZED_TELEGRAM_IDS` is the bootstrap allowlist; you add/remove users
  later with `/allow` and `/disallow` in chat.
- `REDACTION_SALT` means only salted fingerprints of detected secrets are ever
  stored — the values themselves never touch the database.

## Step 4 — Apply migrations and deploy

```bash
# Remote database
npx wrangler d1 migrations apply watchtower-db --remote

# Deploy the Worker
npx wrangler deploy
```

Then register the Telegram webhook (replace with your values):

```bash
curl "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -d "url=https://<your-worker>.workers.dev/telegram?secret=<TELEGRAM_WEBHOOK_SECRET>" \
  -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>"
```

The bot also exposes `setWebhook` logic in `src/telegram/webhook.ts`
(`allowed_updates: ["message"]` only). Open the chat, send `/start` — you will
see your Telegram ID; make sure it matches `AUTHORIZED_TELEGRAM_IDS`, then add
a target with `/add example.com` and run `/scan example.com`.

## Step 5 — Understand the runtime

- **Cron**: one trigger, `*/5 * * * *`. Each tick sends pending Telegram
  notifications first, runs up to 2 scan jobs, schedules scans for targets not
  scanned in the last 30 minutes (`PASSIVE_RESCAN_MINUTES`, read from
  `[vars]`), and purges old rows hourly.
- **Text rules**: the `[[rules]]` block with `type = "Text"` and
  `globs = ["**/fuzz-wordlists/*.txt"]` is what bundles the wordlists. If you
  ever see an import error for a `.txt` file after deploy, check that block
  first (`fallthrough = false` is intentional).
- **Scan tuning** (all in `[vars]`, safe to lower if you want an even smaller
  footprint): `BRUTEFORCE_CHUNK=300`, `BRUTEFORCE_CONCURRENCY=16`,
  `PROBE_LIMIT_PER_SCAN=5`, `FUZZ_REQUESTS_PER_TICK=40`,
  `FREE_TIER_SCAN_TIMEOUT_MS=60000`.
- **Local dev**: `npx wrangler dev` uses `[env.dev]` overrides
  (1 scan job and 5 notifications per tick). D1/KV are emulated locally with
  `npx wrangler d1 migrations apply watchtower-db --local`.

## Troubleshooting

### Bot doesn't respond to `/start`

1. Check `npx wrangler tail` for errors.
2. Verify `AUTHORIZED_TELEGRAM_IDS` contains your Telegram user ID.
3. Verify the webhook is registered:
   `curl "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo" | jq`.
   A `last_error_message` means the Worker threw — check the logs.

### No alerts after a while

1. Is the target active? (`/list` shows status.)
2. Was it scanned recently? (`/list` shows the last scan time.)
3. A repeated scan only reports what is **new** — unchanged assets stay silent
   by design. `/scan <domain>` forces a fresh pass with a summary.

### A `.txt` wordlist fails to bundle after deploy

Re-check the `[[rules]]` Text block in `wrangler.toml` and that the files live
under `fuzz-wordlists/`. `src/wordlists.d.ts` declares the `*.txt` module type
for TypeScript; Wrangler handles the runtime side.

### D1 storage filling up

Old `job_queue` rows are purged after 7 days and `notifications` after
30 days (see `LIMITS` in `src/constants.ts`), automatically on the hourly
tick. Findings and assets are kept — that is the monitoring history.

