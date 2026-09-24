# Watchtower — Incident Response

## When to invoke

1. The bot scanned or probed something you did not intend to (exclusion
   missed, wrong domain added).
2. A secret value appeared in a Telegram message or in the `notifications`
   table.
3. Someone who should not have access issued commands (allowlist too wide,
   account compromised).
4. The bot is flooding a target or Telegram (runaway scan, retry storm).
5. The webhook secret or bot token leaked.

## Severity

| Level | Definition | Example |
|---|---|---|
| SEV-0 | Out-of-scope activity against a third party | Redirect chased to a non-target host |
| SEV-1 | Secret material exposed | Full API key in a chat message |
| SEV-2 | Unauthorized operator access | Ex-allowlisted account issued `/remove` |
| SEV-3 | Noise / self-DoS | Retry storm against your own target |

## Steps

### 1 — Stop (≤ 5 minutes)

- Wrong domain: `/remove <domain>` (cascades all stored data for it).
- Wrong subdomain/path only: `/exclude <domain> <value>` — applied **before
  any request**, so it takes effect on the next probe/fuzz/bruteforce lookup.
- Whole target paused but keep data: `wrangler d1 execute … "UPDATE targets SET status='paused' …"`.
- Unauthorized user: `/disallow <telegram_id>`; if the leak is the bot
  itself, disable the webhook:
  `curl -X POST "https://api.telegram.org/bot<TOKEN>/deleteWebhook"`.
- Retry storm / flooding: pause the target (above) — queued scan jobs for
  paused targets are dropped without retry by the runner.

### 2 — Contain (≤ 30 minutes)

```bash
# What did it touch? (last 24h of notifications, redacted bodies)
npx wrangler d1 execute watchtower-db --remote --command \
  "SELECT created_at, alert_type, severity, title FROM notifications ORDER BY created_at DESC LIMIT 100;"

# What ran?
npx wrangler d1 execute watchtower-db --remote --command \
  "SELECT id, kind, status, attempts, last_error FROM job_queue WHERE created_at > datetime('now','-1 day');"

# Snapshot the database
npx wrangler d1 export watchtower-db --remote > snapshot-INC.sql
```

### 3 — Eradicate (≤ 4 hours)

Rotate the compromised secrets (exactly four exist):

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN        # new token from @BotFather if leaked
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET   # any long random string
npx wrangler secret put AUTHORIZED_TELEGRAM_IDS   # rebuild the allowlist
npx wrangler secret put REDACTION_SALT            # NOTE: changes future fingerprints
```
> Rotating `REDACTION_SALT` invalidates cross-comparison with fingerprints
> recorded under the old salt — previously seen secrets may re-alert once.

Then `npx wrangler deploy` (secrets apply on next deploy/restart) and
re-register the webhook (see DEPLOYMENT.md, Step 4).

### 4 — Recover (≤ 24 hours)

1. Re-add legitimate domains: `/add <domain> [category]`.
2. Run `/scan <domain>` and confirm the summary looks right.
3. Re-enable `/feature` flags you disabled during containment.
4. Notify the affected program owner if their scope was touched (template
   below).

### 5 — Postmortem (≤ 7 days)

Document timeline + root cause, add a regression test (the suite is
`npm test` — 18 files), and update `docs/threat-model.md`.

## Communication templates

**Internal**

> Incident: INC-YYYYMMDD-NNN · SEV-N
> Detected: <ISO time> · Contained: <yes/no>
> Summary: <one paragraph> · Owner: <name>

**External (program owner)**

> We detected monitoring activity affecting your program's scope on <date>
> that was not intended. We paused it immediately (<action taken>) and are
> reviewing our configuration. No intrusive testing (exploitation, credential
> use, destructive actions) was performed — Watchtower only issues GET/HEAD
> requests and passive DNS/CT lookups. Contact: <your address>
