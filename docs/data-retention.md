# Watchtower — Data Retention Policy

## Overview

Watchtower retains data only as long as needed to support authorized
security monitoring, audit, and incident response. After retention windows
expire, data is permanently deleted from D1, R2, and KV.

## Retention windows

| Data class | Default retention | Source |
|------------|-------------------|--------|
| Evidence (HTTP responses, JS snapshots, scanner output) | 180 days | `EVIDENCE_RETENTION_DAYS` env var |
| Findings | Until target is decommissioned | (No automatic deletion) |
| Audit logs | 730 days (2 years) | `AUDIT_RETENTION_DAYS` env var |
| JavaScript file hashes | Same as evidence | Derived from evidence retention |
| DNS records | Until asset removed | Marked `removed_at`; purged after 90 days |
| Certificates | Until asset removed | Marked `removed_at`; purged after 90 days |
| Notifications | 90 days | (configurable per-integration) |
| API tokens | Configurable, max 90 days | `expires_at` column |
| Reports | 365 days | R2 lifecycle rule |
| Provider cache (KV) | 5 minutes | `expirationTtl` on KV puts |

## Per-organization overrides

Organizations can override the defaults via the `retention_policies` table:

```sql
INSERT INTO retention_policies (id, organization_id, data_class, retention_days)
VALUES ('rp_1', 'ORG_xxx', 'evidence', 90);
```

Valid `data_class` values: `evidence`, `findings`, `audit`, `javascript`,
`dns`, `certificates`, `reports`.

## Deletion process

A scheduled cron job (configured in `wrangler.toml` under `[triggers]`)
runs daily to purge expired data:

1. **Evidence**: list R2 objects with `expires-at` metadata older than
   today; delete each. This is a hard delete (no soft-delete layer).
2. **DNS/certificates**: rows with `removed_at` older than 90 days are
   hard-deleted via `DELETE FROM ... WHERE removed_at < ?`.
3. **Audit logs**: rows older than `AUDIT_RETENTION_DAYS` are deleted.
4. **Notifications**: rows older than 90 days are deleted.
5. **API tokens**: rows with `expires_at < now()` are deleted.
6. **Provider cache**: KV TTLs handle this automatically.

## Right to be forgotten

Operators can request deletion of a target's entire footprint:

1. `DELETE FROM targets WHERE id = ?` cascades to scope_entries, assets,
   dns_records, certificates, services, technologies, javascript_files,
   javascript_diffs, api_endpoints, scans, scan_jobs, scan_results,
   findings, finding_evidence, finding_comments, finding_history, changes,
   schedules, reports.
2. R2 evidence under `evidence/<org_id>/<target_id>/` is deleted via a
   `list` + `delete` loop.

This operation is **irreversible** and is audit-logged.

## Legal hold

When a legal hold is in place, set the `paused` flag on the target to
prevent deletion. A documented exception process is required to override.
