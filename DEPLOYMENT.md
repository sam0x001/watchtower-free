# Watchtower — Deployment Guide

## Prerequisites

- Node.js 20+ (use `.nvmrc`)
- Wrangler CLI (`npm install -g wrangler` or use `npx wrangler`)
- A Cloudflare account with Workers paid plan (required for Queues + D1 + DO)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

## Step 1 — Install dependencies

```bash
npm install
```

## Step 2 — Provision Cloudflare resources

```bash
# D1 database
npx wrangler d1 create watchtower-db
# Copy the database_id into wrangler.toml

# KV namespace (non-critical cache only)
npx wrangler kv namespace create CACHE
# Copy the id into wrangler.toml

# R2 bucket (encrypted evidence + reports)
npx wrangler r2 bucket create watchtower-evidence

# Queues
npx wrangler queues create watchtower-scans
npx wrangler queues create watchtower-scans-dlq
npx wrangler queues create watchtower-notifications
npx wrangler queues create watchtower-notifications-dlq
```

## Step 3 — Apply DB migrations

```bash
# Local (for dev)
npx wrangler d1 migrations apply watchtower-db --local

# Production
npx wrangler d1 migrations apply watchtower-db --remote
```

## Step 4 — Set secrets

Generate strong secrets:

```bash
# 32 bytes for AES-GCM (base64-encoded)
openssl rand -base64 32

# 64-char hex for HMAC
openssl rand -hex 32
```

Set them via `wrangler secret put`:

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET
npx wrangler secret put AUTHORIZED_TELEGRAM_IDS        # comma-separated Telegram user IDs
npx wrangler secret put ENCRYPTION_KEY                  # base64 32 bytes
npx wrangler secret put API_HMAC_KEY
npx wrangler secret put WEBHOOK_SIGNING_SECRET
npx wrangler secret put RUNNER_REGISTRY_TOKEN

# Optional integrations
npx wrangler secret put SLACK_BOT_TOKEN
npx wrangler secret put JIRA_API_TOKEN
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put SENDGRID_API_KEY
npx wrangler secret put NVD_API_KEY
```

## Step 5 — Deploy

```bash
npx wrangler deploy
```

Note the deployed URL (e.g. `https://watchtower.YOUR-SUBDOMAIN.workers.dev`).

## Step 6 — Register the Telegram webhook

Use [@BotFather](https://t.me/BotFather) to set your webhook:

```bash
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
  -H "content-type: application/json" \
  -d "$(jq -n --arg url "https://watchtower.YOUR-SUBDOMAIN.workers.dev/telegram?secret=$TELEGRAM_WEBHOOK_SECRET" \
    --arg token "$TELEGRAM_WEBHOOK_SECRET" \
    '{url:$url, allowed_updates:["message","callback_query"], secret_token:$token}')"
```

Alternatively, call `setWebhook` programmatically — see
`src/telegram/webhook.ts` for the helper.

## Step 7 — Bootstrap the operator

1. From your authorized Telegram account, send `/start` to the bot.
2. Create an organization in D1:
   ```sql
   INSERT INTO organizations (id, name, slug, created_at)
   VALUES ('ORG_main', 'Main Org', 'main', datetime('now'));
   ```
3. Create your user record (the bot does this on `/team_invite`, but you can also insert directly):
   ```sql
   INSERT INTO users (id, telegram_id, display_name, organization_id, role, created_at)
   VALUES ('USR_owner', '<YOUR_TELEGRAM_ID>', 'Owner', 'ORG_main', 'owner', datetime('now'));

   INSERT INTO memberships (user_id, organization_id, role, created_at)
   VALUES ('USR_owner', 'ORG_main', 'owner', datetime('now'));
   ```
4. Add your first target:
   ```
   /target_add ORG_main example.com 2099-12-31 https://bugbounty.example.com/rules
   ```
5. Authorize the target:
   ```
   /authorize example.com BUGBOUNTY-PROGRAM-001
   ```
6. Add scope:
   ```
   /scope_add <target_id> wildcard_domain *.example.com
   ```
7. Run your first passive scan:
   ```
   /scan_passive <target_id>
   ```

## Step 8 — Register an external scanner runner

The runner protocol is defined in `src/providers/scanners/runner-protocol.ts`.
A reference runner is provided as a separate repository (link TBD). To
register a runner:

```sql
INSERT INTO runners (id, name, owner_user_id, pubkey, allowed_tools_json, network_egress_allowlist_json, created_at)
VALUES ('RUNNER_1', 'prod-runner-1', 'USR_owner', '<ed25519-pubkey>',
        '["nmap","subfinder","httpx","nuclei"]',
        '["https://crt.sh","https://dns.google","https://api.osv.dev"]',
        datetime('now'));
```

## Staging / dev environments

`wrangler.toml` defines `[env.staging]` and `[env.dev]` sections. Deploy to
staging with:

```bash
npx wrangler deploy --env staging
```

For local dev:

```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your dev secrets
npx wrangler dev
```

## Observability

- Workers logs: `npx wrangler tail`
- D1 queries: `npx wrangler d1 execute watchtower-db --remote --command "..."`
- Audit log: `SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100;`

## Backups

- D1: `npx wrangler d1 export watchtower-db --remote --output backup.sql`
- R2: use lifecycle rules to copy evidence to a cold-storage bucket.
- KV: ephemeral cache only; no backup needed.

## Updating

```bash
git pull
npx wrangler d1 migrations apply watchtower-db --remote
npx wrangler deploy
```
