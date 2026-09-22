-- ===========================================================================
-- Watchtower migration 0012 - reconcile audit_logs with the canonical schema
-- ===========================================================================
-- Incident (2026-09-21): the remote audit_logs table had been extended by hand
-- (outside of migrations) with a second, redundant column set:
--
--   request_id, timestamp, user_id, telegram_id, action, args_redacted, error, ip
--
-- while the runtime code wrote ONLY those columns. Because the canonical NOT
-- NULL columns were left unset, every audit write failed with:
--
--   D1_ERROR: NOT NULL constraint failed: audit_logs.actor_kind: SQLITE_CONSTRAINT
--
-- The code now writes the canonical columns exclusively (see
-- src/audit/logger.ts -> AUDIT_INSERT_SQL), so this migration only removes the
-- leftover columns. The table is REBUILT rather than using
-- "ALTER TABLE ... DROP COLUMN" so that this migration also succeeds on
-- databases created purely from migrations (which never had those columns,
-- making a DROP COLUMN fail with "no such column").
--
-- Only canonical columns are referenced, so the migration is shape-agnostic.
-- The row copy is lossless: rows written through the buggy path cannot exist,
-- because actor_kind, command, result and created_at are NOT NULL and were
-- never supplied by that path (verified: the table was empty when this
-- migration was authored).

DROP TABLE IF EXISTS audit_logs_reconciled;

CREATE TABLE audit_logs_reconciled (
  id                 TEXT PRIMARY KEY,
  organization_id    TEXT,
  actor_user_id      TEXT,
  actor_kind         TEXT NOT NULL CHECK (actor_kind IN ('telegram','api','system','runner','webhook')),
  actor_identity     TEXT,
  command            TEXT NOT NULL,
  target_id          TEXT,
  scope_id           TEXT,
  job_id             TEXT,
  runner_id          TEXT,
  scanner            TEXT,
  arguments_redacted TEXT,
  result             TEXT NOT NULL CHECK (result IN ('success','denied','error','pending_approval')),
  result_detail      TEXT,
  approval_decision  TEXT CHECK (approval_decision IN ('approved','rejected','auto','not_required')),
  approved_by        TEXT,
  request_metadata   TEXT,
  correlation_id     TEXT,
  created_at         TEXT NOT NULL
);

INSERT INTO audit_logs_reconciled (
  id, organization_id, actor_user_id, actor_kind, actor_identity, command,
  target_id, scope_id, job_id, runner_id, scanner, arguments_redacted,
  result, result_detail, approval_decision, approved_by, request_metadata,
  correlation_id, created_at
)
SELECT
  id, organization_id, actor_user_id, actor_kind, actor_identity, command,
  target_id, scope_id, job_id, runner_id, scanner, arguments_redacted,
  result, result_detail, approval_decision, approved_by, request_metadata,
  correlation_id, created_at
FROM audit_logs;

DROP TABLE audit_logs;

ALTER TABLE audit_logs_reconciled RENAME TO audit_logs;

CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_logs (correlation_id);
