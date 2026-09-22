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

This applies the incremental migration files (`0001_initial.sql` through
`0012_audit_logs_reconcile.sql`) plus the seed file. `0011_evidence_d1.sql`
creates the `evidence_blobs` table that replaces R2 for evidence storage, and
`0012_audit_logs_reconcile.sql` restores `audit_logs` to its canonical column
set (see below).

### Never change the schema by hand

**Always change the schema with a migration file in `migrations/` — never with
`npx wrangler d1 execute --command "ALTER TABLE ..."`.** Hand-run DDL is
invisible to git, invisible to `wrangler d1 migrations list`, and invisible to
everyone else deploying this repo. It is exactly how the `audit_logs` incident
happened: extra columns were added straight to the remote database, the Worker
kept writing only those columns, and every audit insert started failing with
`NOT NULL constraint failed: audit_logs.actor_kind`.

`audit_logs` is the canary, because it is written on every Telegram command,
scan, API call and webhook, and it is the only table with `NOT NULL` actor
columns. If a deploy starts throwing database errors, check for schema drift
first — the local and remote column lists must match exactly:

```bash
npx wrangler d1 execute watchtower-db --local  --command "PRAGMA table_info(audit_logs);"
npx wrangler d1 execute watchtower-db --remote --command "PRAGMA table_info(audit_logs);"
```

If they differ, see the Troubleshooting section below before deploying again.

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

Replace the placeholders and run [webhook-tester.sh](./scripts/webhook-tester.sh) which is in `scripts/webhook-tester.sh`:

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

- Workers logs: `npx wrangler tail` — live stream of the deployed Worker's
  console output (see [Debugging a live Worker](#debugging-a-live-worker-with-npx-wrangler-tail))
- D1 queries: `npx wrangler d1 execute watchtower-db --remote --command "..."`
- Audit log:
  ```bash
  npx wrangler d1 execute watchtower-db --remote --command \
    "SELECT created_at, command, actor_identity, result, result_detail FROM audit_logs ORDER BY created_at DESC LIMIT 20;"
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

## Debugging a live Worker with `npx wrangler tail`

`npx wrangler tail` opens a live stream of everything your **deployed** Worker
logs: every `console.log` / `warn` / `error`, every uncaught exception, and every
cron invocation. It is the fastest way to find out *why* the bot replied
"❌ Command failed" — the terminal shows the real error string, which never
reaches Telegram.

```bash
npx wrangler tail                  # stream all invocations
npx wrangler tail --status error   # only invocations that threw
npx wrangler tail --format json    # machine-readable, one JSON object per line
```

Leave it running in one terminal while you exercise the bot from another
(Telegram, `curl`, the dashboard). Telegram never needs to retry anything:
Watchtower acks the webhook immediately and does the work in `ctx.waitUntil()`,
so log lines appear just *after* the webhook returns `200`.

A single request looks like this (Wrangler's default `pretty` format):

```
POST https://watchtower.<subdomain>.workers.dev/telegram?secret=... - Ok @ 9/21/2026, 2:31:12 PM
  (error) {"level":"error","msg":"telegram.process_update.failed","err":"Error: D1_ERROR: NOT NULL constraint failed: audit_logs.actor_kind: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_NOTNULL)","requestId":"req_TAcO0eiXf0g7"}
```

### Filtering the stream

| Flag | Use it for |
|---|---|
| `--status error` | only failed invocations — the one you want while debugging |
| `--format json` | piping into `jq` (`jq 'select(.level=="error")'`) or unreadable colour output |
| `--search "<text>"` | substring match in a log message, e.g. `--search requestId` |
| `--method POST` | isolate `/telegram` webhook traffic (always `POST`) |
| `--method GET` | isolate `/v1/*` reads from your own tooling |
| `--header "cf-connecting-ip: 203.0.113.7"` | a single client's requests |
| `--ip self` | only requests you make yourself (health checks, `curl /v1/*`) |
| `--sampling-rate 0.5` | sample 50% of invocations on a busy Worker |
| `--version-id <id>` | confirm which deployed version is actually serving traffic |

Ctrl+C ends the session. Nothing is stored afterwards by `tail` itself, but
because `[observability]` is enabled in `wrangler.toml` the same entries are
also browsable in the Cloudflare dashboard (Workers → watchtower → Logs).

On Windows PowerShell, quote patterns that contain `$`, `{` or spaces:
`npx wrangler tail --search 'requestId'`.

### Reading Watchtower's logs

Every line is a JSON object emitted by `src/audit/logger.ts`
(`makeConsoleLogger`), so it always carries `level` (`debug`/`info`/`warn`/`error`)
and `msg`, usually plus context fields. The names worth grepping for:

| Message | Level | Meaning |
|---|---|---|
| `telegram.process_update.failed` | error | the whole Telegram update failed — `err` holds the real cause, `requestId` ties it to `audit_logs.correlation_id` |
| `telegram.command.<command>.failed` | error | one handler (`/scan`, `/audit`, …) threw; the sender also saw `❌ Command failed: …` |
| `api.route_error` | error | an `/v1/*` handler threw; `path` and `requestId` are included |
| `webhook.blocked_private_target` | warn | SSRF protection rejected a private/reserved host |
| `cron.tick_complete` | info | a cron tick finished (fields: `time`, `notifications`, `scans`, `scansEnqueued`, `expiredTargets`, `warningTargets`) |
| `cron.run_scans_failed`, `cron.dispatch_notifications_failed` | warn | that stage of the tick failed; the tick still completes |
| `cron.stale_jobs_expire_failed`, `cron.purge_evidence_failed` | warn | cleanup stage failed (fine once, investigate if it repeats) |
| `slack.disabled_no_token`, `jira.disabled_no_token`, `github.disabled_no_config`, `email.disabled_no_config` | warn | that integration simply isn't configured |

### Debug workflow

1. Start `npx wrangler tail --status error` in one terminal.
2. Reproduce the problem — send the command to the bot, or hit the Worker.
3. Read the `err` field, then note the `requestId`.
4. Correlate the failure with the audit trail:

   ```bash
   npx wrangler d1 execute watchtower-db --remote --command \
     "SELECT created_at, command, actor_kind, result, result_detail, correlation_id FROM audit_logs ORDER BY created_at DESC LIMIT 10;"
   ```

5. No matching audit row at all? Then the request died *before* the audit write:
   a wrong `?secret=`, a body that isn't JSON (`400 Bad Request`), or a failed
   D1 insert. Check `npx wrangler tail --method POST`, and the webhook status:

   ```bash
   curl "https://api.telegram.org/bot<your-bot-token>/getWebhookInfo" | jq
   ```

6. Cron problems never show an HTTP request line. Run
   `npx wrangler tail --format json --status error` and look for `cron.*`
   entries; a healthy tick reports `cron.tick_complete`, so compare against a
   working one before hunting further.
7. Fix, `npx wrangler deploy`, repeat the action and confirm the error is gone —
   `tail` keeps streaming across deploys, so you can watch the same Worker
   through the whole fix.

### Debugging locally instead of in production

`npx wrangler dev` prints the same JSON lines to your terminal but uses the
**local** D1 database (`.wrangler/state/`), so you can iterate without touching
production data or spamming your real chat:

```bash
npx wrangler d1 migrations apply watchtower-db --local   # once, or after pulling new migrations
npx wrangler dev
```

Then replay an update against the local Worker (secrets come from `.dev.vars`,
see `.dev.vars.example`):

```bash
curl -X POST "http://localhost:8787/telegram?secret=$TELEGRAM_WEBHOOK_SECRET" \
  -H "content-type: application/json" \
  -d '{"update_id":1,"message":{"message_id":1,"chat":{"id":123,"type":"private"},"from":{"id":123,"is_bot":false,"username":"you"},"text":"/help","date":0}}'
```

**Keep tokens out of committed files.** `.dev.vars` and `.env` are gitignored;
put secrets in shell variables or `.dev.vars`, never in a `.sh` you might commit.

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

Migrations in this repo are additive, so migrating before deploying is normally
safe. The exception is a migration that **removes or renames** columns the
currently deployed Worker still writes — for example
`0012_audit_logs_reconcile.sql`, which drops leftover `audit_logs` columns. For
those, deploy first and migrate second:

```bash
git pull
npx wrangler deploy                                     # code that only uses current columns
npx wrangler d1 migrations apply watchtower-db --remote  # then change the schema
```

`./scripts/deploy.sh` follows this order (deploy, then migrate) for exactly this
reason. Keep `npx wrangler tail --status error` open while you update — it is the
only way to catch a bad release before your users do.

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

### D1_ERROR: NOT NULL constraint failed: audit_logs.actor_kind

Full symptom in `npx wrangler tail`:

```
(error) {"level":"error","msg":"telegram.process_update.failed","err":"Error: D1_ERROR: NOT NULL constraint failed: audit_logs.actor_kind: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_NOTNULL)"}
```

`audit_logs` has `NOT NULL` columns (`actor_kind`, `command`, `result`,
`created_at`), so the Worker must supply all of them on every insert. This error
means the database and the deployed code disagree about the table's columns —
almost always because the remote schema was modified by hand instead of through
a migration file. The mirror-image symptom is
`D1_ERROR: no such column: audit_logs.request_id`.

Diagnose (the two column lists must match exactly):

```bash
npx wrangler d1 execute watchtower-db --local  --command "PRAGMA table_info(audit_logs);"
npx wrangler d1 execute watchtower-db --remote --command "PRAGMA table_info(audit_logs);"
```

Repair:

1. `git pull` so you have a release whose Worker writes the canonical columns,
   then deploy it: `npx wrangler deploy`.
2. Apply every migration, including the reconciling one:
   `npx wrangler d1 migrations apply watchtower-db --remote`.
   `0012_audit_logs_reconcile.sql` rebuilds `audit_logs` with exactly the
   canonical columns, so any hand-added columns disappear.
3. Re-run `PRAGMA table_info(audit_logs)` — you should see 19 columns, ending in
   `correlation_id`, `created_at`.
4. Trigger a command in Telegram with `npx wrangler tail --status error` open —
   no more `NOT NULL` errors.

**Order matters here:** deploy the code *before* a migration that removes
columns the running Worker still writes, otherwise the live Worker fails with
`no such column` in the window between the two commands. Purely additive
migrations are safe in either order (see Updating below).

### "incomplete input: SQLITE_ERROR" from `wrangler d1 execute`

`--command` takes a single statement, and newlines inside the argument get
mangled — D1 then sees a truncated query:

```
✘ [ERROR] A request to the Cloudflare API (/accounts/.../d1/database/.../query) failed.
  incomplete input: SQLITE_ERROR [code: 7500]
```

Keep `--command` to one-liners (`--command "SELECT COUNT(*) FROM audit_logs;"`)
and put anything longer or multi-statement in a file (create it first):

```bash
npx wrangler d1 execute watchtower-db --remote --file=query.sql
```

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
