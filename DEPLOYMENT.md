# Watchtower — Free-Tier Deployment Guide

This guide deploys Watchtower on Cloudflare's **free tier only** — no payment
method required, $0/month. Queues and Durable Objects are replaced with
D1-backed equivalents. R2 is optional and falls back to D1 BLOB storage.

## Prerequisites

- Node.js 20+ (use `.nvmrc`)
- Wrangler CLI (`npm install -g wrangler` or use `npx wrangler`)
- A Cloudflare account (free plan, no payment method needed)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

## Step 1 — Install dependencies

```bash
npm install
```

## Step 2 — Provision Cloudflare resources (FREE TIER)

```bash
# D1 database (relational metadata, job_queue, findings, audit logs, evidence)
npx wrangler d1 create watchtower-db
# Copy the database_id into wrangler.toml

# KV namespace (non-critical cache only)
npx wrangler kv:namespace create CACHE
# Copy the id into wrangler.toml

# OPTIONAL: R2 buckets — only if you have a payment method on file.
# Skip these on the free tier. Watchtower auto-detects R2 absence and
# falls back to storing encrypted evidence as TEXT in the D1 database.
#
# npx wrangler r2 bucket create watchtower-evidence
# npx wrangler r2 bucket create watchtower-reports
#
# If you see "Please enable R2 through the Cloudflare Dashboard [code: 10042]"
# it means R2 isn't enabled on your account — that's FINE, just skip R2.
```

**Do NOT run** `wrangler queues create ...` — Queues require the paid plan.
Watchtower uses a D1 `job_queue` table instead.

## Step 3 — Edit `wrangler.toml`

Replace the placeholder IDs with the values from step 2:

```toml
[[d1_databases]]
binding = "DB"
database_name = "watchtower-db"
database_id = "PASTE_YOUR_D1_DATABASE_ID_HERE"

[[kv_namespaces]]
binding = "CACHE"
id = "PASTE_YOUR_KV_NAMESPACE_ID_HERE"
preview_id = "PASTE_YOUR_KV_NAMESPACE_ID_HERE"
```

The R2 blocks in `wrangler.toml` are commented out by default. Leave them
commented — Watchtower will use D1 for evidence storage.

If you don't have a custom domain, remove or comment out the `[[routes]]`
block. The Worker will be reachable at `https://watchtower.<random>.workers.dev`.

## Step 4 — Apply DB migrations

```bash
# Local (for dev)
npx wrangler d1 migrations apply watchtower-db --local

# Production (remote)
npx wrangler d1 migrations apply watchtower-db --remote
```

This applies 12 incremental migration files (`0001_initial.sql` through
`0011_evidence_d1.sql`) plus the seed file. The last migration creates
the `evidence_blobs` table that replaces R2 for evidence storage.

## Step 5 — Generate strong secrets

```bash
# 32 bytes base64 — for AES-GCM at-rest encryption
openssl rand -base64 32

# 32 bytes hex — for HMAC signing + redaction salt
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Save all of these in a password manager — they're not recoverable once set.

## Step 6 — Set Cloudflare secrets

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
# → paste your Telegram bot token from BotFather

npx wrangler secret put TELEGRAM_WEBHOOK_SECRET
# → paste one of the hex values you generated

npx wrangler secret put AUTHORIZED_TELEGRAM_IDS
# → paste your numeric Telegram user ID (just the number, no quotes)

npx wrangler secret put ENCRYPTION_KEY
# → paste the base64 value (for AES-GCM)

npx wrangler secret put REDACTION_SALT
# → paste a hex value (for salted secret fingerprints)

npx wrangler secret put API_HMAC_KEY
# → paste a hex value (for HMAC-signed tokens)

npx wrangler secret put WEBHOOK_SIGNING_SECRET
# → paste a hex value

npx wrangler secret put RUNNER_REGISTRY_TOKEN
# → paste a hex value
```

Each command prompts for the value interactively — never paste secrets directly
into `wrangler.toml` or commit them to git.

## Step 7 — Deploy the Worker

```bash
npx wrangler deploy
```

You'll see output like:

```
Published watchtower (1.23 sec)
  https://watchtower.<your-subdomain>.workers.dev
  Current Version ID: abc-123-def-456
```

Note the URL — you'll need it in step 8.

## Step 8 — Register the Telegram webhook

Replace the placeholders and run:

```bash
WEBHOOK_URL="https://watchtower.YOUR-SUBDOMAIN.workers.dev"
SECRET="your-TELEGRAM_WEBHOOK_SECRET-hex-value"
BOT_TOKEN="your-TELEGRAM-BOT-TOKEN"

curl "https://api.telegram.org/bot${BOT_TOKEN}/setWebhook" \
  -H "content-type: application/json" \
  -d "$(jq -n \
    --arg url "${WEBHOOK_URL}/telegram?secret=${SECRET}" \
    --arg token "${SECRET}" \
    '{url:$url, allowed_updates:["message","callback_query"], secret_token:$token}'
  )"
```

Expected response:
```json
{"ok":true,"result":true,"description":"Webhook was set"}
```

Verify:
```bash
curl "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo" | jq
```

## Step 9 — Bootstrap the organization + your user

You can't do this via Telegram yet because you don't have an org to be a
member of. Run these directly against D1:

```bash
# Create an organization
npx wrangler d1 execute watchtower-db --remote --command \
  "INSERT INTO organizations (id, name, slug, created_at, updated_at)
   VALUES ('ORG_main', 'Main Org', 'main', datetime('now'), datetime('now'));"

# Create your user (replace TELEGRAM_ID with your actual numeric ID)
npx wrangler d1 execute watchtower-db --remote --command \
  "INSERT INTO users (id, telegram_user_id, telegram_username, display_name, is_active, created_at, updated_at)
   VALUES ('USR_owner', 'YOUR_TELEGRAM_ID', 'yourhandle', 'Owner', 1, datetime('now'), datetime('now'));"

# Make yourself the owner of the org
npx wrangler d1 execute watchtower-db --remote --command \
  "INSERT INTO memberships (id, organization_id, user_id, role_id, status, mfa_required, allowed_chat_ids, created_at, updated_at)
   VALUES ('MBR_1', 'ORG_main', 'USR_owner',
           (SELECT id FROM roles WHERE name='owner' LIMIT 1),
           'active', 0, '[]', datetime('now'), datetime('now'));"
```

## Step 10 — Send `/start` to your bot

1. Open your bot in Telegram (search for the username you created with BotFather)
2. Send `/start`

You should see the welcome screen with quick-start instructions. If you get
"Unauthorized", your `AUTHORIZED_TELEGRAM_IDS` is wrong — re-set the secret
with your correct Telegram user ID.

## Step 11 — Add your first target

In the Telegram chat:

```
/authorize example.com WRITTEN-CONTRACT-2026-001
```

```
/target_add ORG_main example.com 2099-12-31
```

The bot replies with a target ID like `TGT_abc123`. Note it.

## Step 12 — Add scope

Scope = the hosts/IPs/URLs you're authorized to monitor. Without scope, no
scan runs.

```
/scope_add TGT_abc123 wildcard_domain *.example.com
/scope_add TGT_abc123 domain example.com
```

If there's an excluded subdomain (e.g. `internal.example.com` is production
billing and must not be touched):

```
/scope_add TGT_abc123 domain internal.example.com --exclude
```

## Step 13 — Wait for the first scan

The cron trigger fires every 5 minutes. Within ~5 minutes, you'll see:

```
📋 [MEDIUM] New subdomain discovered: www.example.com

Target: example.com
Change type: new_subdomain
Hostname: www.example.com
Source: crt.sh
Confidence: 0.95

Use /diff_latest to see all recent changes or /finding_details to inspect a specific finding.
```

The first scan produces a flood of `new_*` alerts (every discovered asset is
"new"). Subsequent scans only alert on **delta** — assets not previously seen,
or assets whose state changed.

## Step 14 — Manual scan (optional)

Don't want to wait for the cron? Trigger a scan immediately:

```
/scan_passive TGT_abc123
```

The bot inserts a row into `job_queue` and the next cron tick (within 5 min)
picks it up.

## Free-tier limits to keep in mind

| Limit | How Watchtower respects it |
|---|---|
| 100k Worker requests/day | Cron fires 288×/day + Telegram webhook — well under 100k |
| 10ms CPU per invocation | Scan work runs in `ctx.waitUntil()` (30s wall-clock); CPU stays low because providers are I/O-bound |
| 1 Cron Trigger | Single `*/5 * * * *` with internal time-of-day dispatch |
| D1: 5M reads + 100k writes/day | ~14k writes/day max — well under limit |
| D1: 5 GB storage | `purgeOldJobs()` + `purgeExpiredEvidence()` run hourly; retention windows shortened |
| R2: requires payment method | **R2 is optional** — Watchtower falls back to D1 BLOB storage |
| KV: 100k reads + 1k writes/day | Used only for provider response caching (5-min TTL) |

## Observability

- Workers logs: `npx wrangler tail`
- D1 queries: `npx wrangler d1 execute watchtower-db --remote --command "..."`
- Audit log:
  ```bash
  npx wrangler d1 execute watchtower-db --remote --command \
    "SELECT timestamp, action, telegram_id, result, error FROM audit_logs ORDER BY timestamp DESC LIMIT 20;"
  ```
- Job queue:
  ```bash
  npx wrangler d1 execute watchtower-db --remote --command \
    "SELECT id, kind, status, attempts, created_at, started_at FROM job_queue ORDER BY created_at DESC LIMIT 20;"
  ```
- Notifications:
  ```bash
  npx wrangler d1 execute watchtower-db --remote --command \
    "SELECT id, channel, severity, status, last_error, created_at FROM notifications ORDER BY created_at DESC LIMIT 20;"
  ```

## Backups

- D1: `npx wrangler d1 export watchtower-db --remote --output backup.sql`
- KV: ephemeral cache only — no backup needed
- Evidence (D1 BLOBs): included in the D1 export above

## Updating

```bash
git pull
npx wrangler d1 migrations apply watchtower-db --remote
npx wrangler deploy
```

## Troubleshooting

### "Please enable R2 through the Cloudflare Dashboard [code: 10042]"

You ran `wrangler r2 bucket create ...` — **don't**. R2 is optional on the
free tier. Skip R2 entirely; Watchtower uses D1 BLOB storage by default.

### "Workers Free plan doesn't support Durable Objects"

Make sure you deployed the free-tier version (`watchtower-free.zip`), not the
paid-tier version (`watchtower-v2.zip`). The free version has no DO bindings
in `wrangler.toml`.

### "Workers Free plan doesn't support Queues"

Same as above — make sure you're using `watchtower-free.zip`. The free version
uses a D1 `job_queue` table instead of Cloudflare Queues.

### Bot doesn't respond to `/start`

1. Check `wrangler tail` for errors
2. Verify `AUTHORIZED_TELEGRAM_IDS` secret matches your Telegram user ID
3. Verify the webhook is registered: `curl "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo" | jq`
4. If `last_error_message` is set in the webhook info, the Worker is throwing — check logs

### No alerts after 15 minutes

1. Check the `job_queue` table — are there pending scan jobs?
2. Check the `audit_logs` table — did the scan complete or fail?
3. Check the `notifications` table — were notifications enqueued? What's their `status`?
4. Check that your user row in `users` has the correct `telegram_user_id`
5. Check that your membership row has `role='owner'` and `status='active'`

### Scan jobs stuck in `running` status

The cron's `autoExpireStaleJobs()` should clean these up on the next tick
(marks them `failed` after 5 min). If they're stuck, run:

```bash
npx wrangler d1 execute watchtower-db --remote --command \
  "UPDATE job_queue SET status = 'failed', last_error = 'manual cleanup' WHERE status = 'running' AND locked_until < datetime('now');"
```

### D1 storage filling up

Reduce retention windows in `wrangler.toml`:

```toml
EVIDENCE_RETENTION_DAYS = "30"   # down from 90
JS_SNAPSHOT_RETENTION_DAYS = "14"  # down from 30
AUDIT_RETENTION_DAYS = "30"   # down from 90
```

Then redeploy. The next hourly cron tick will purge old rows.
