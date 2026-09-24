# Watchtower — Data Retention

## What is kept

Everything lives in D1 (plus two small KV cursor families). There is no R2,
no evidence store, and no audit log in v4.

| Data | Retention | Enforced by |
|---|---|---|
| Targets, scopes/exclusions, categories | Until `/remove` | manual |
| Assets, DNS records, certificates, services, technologies, JS files, API endpoints | Until `/remove` (FK cascade) | manual |
| Findings | Until `/remove` (FK cascade) — kept forever otherwise | manual |
| Scans history | Until `/remove` | manual |
| `job_queue` rows | **7 days** (`LIMITS.JOB_RETENTION_DAYS`) | hourly cron purge |
| `notifications` log | **30 days** (`LIMITS.NOTIFICATION_RETENTION_DAYS`) | hourly cron purge |
| `target_features` toggles | Until the domain is removed | FK cascade |
| KV `bf:*` / `fuzz:*` / `pw:*` cursors | Last write wins; wrap around on completion | replaced on next tick |
| KV `wc:*` wildcard-DNS cache | **7 days** | KV `expirationTtl` |

Retention constants live in `src/constants.ts` (`LIMITS`); purge runs once an
hour on the cron tick (`minuteOfDay % 60 === 0`).

## Deletion

- `/remove <domain>` — `DELETE FROM targets` cascades to scopes, assets
  (+ everything keyed by them), scans, findings, and feature toggles. The
  domain's KV cursors stop being updated (orphaned keys expire by non-use;
  they hold only cursors, no content).
- Deleting a **category** (`target_groups` row) only detaches its domains
  (`ON DELETE SET NULL`) — domains and their data are never deleted with it.
- Notifications are *not* tied to a target FK; they age out on the 30-day
  purge.

## What is never stored

- Secret values — only salted fingerprints (see SECURITY.md)
- Full HTTP response bodies from fuzzing (only status/length/title/hash)
- Credentials, cookies, or authorization headers on outbound requests

## Manual purge (if you need it now)

```bash
npx wrangler d1 execute watchtower-db --remote --command \
  "DELETE FROM job_queue WHERE status IN ('completed','failed','cancelled','dead_letter') AND created_at < date('now','-7 day');"
npx wrangler d1 execute watchtower-db --remote --command \
  "DELETE FROM notifications WHERE created_at < date('now','-30 day');"
```
