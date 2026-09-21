-- ===========================================================================
-- Watchtower migration 0007 - wordlists, reports, idempotency, DLQ
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS wordlists (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  version          TEXT NOT NULL,
  category         TEXT NOT NULL
                   CHECK (category IN ('directories','files','backups','config','api_paths','api_versions','graphql','docs','static_assets','javascript','source_maps','subdomain_prefixes','cloud_patterns','technology_specific','custom')),
  source           TEXT NOT NULL,
  description      TEXT,
  r2_key           TEXT NOT NULL,
  entry_count      INTEGER NOT NULL DEFAULT 0,
  max_word_length  INTEGER NOT NULL DEFAULT 256,
  content_hash     TEXT NOT NULL,
  license_note     TEXT,
  requires_authorization INTEGER NOT NULL DEFAULT 1 CHECK (requires_authorization IN (0,1)),
  is_builtin       INTEGER NOT NULL DEFAULT 0 CHECK (is_builtin IN (0,1)),
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_by       TEXT REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (organization_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_wordlists_category ON wordlists (organization_id, category, enabled);

CREATE TABLE IF NOT EXISTS wordlist_runs (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  job_id           TEXT REFERENCES scan_jobs(id) ON DELETE CASCADE,
  wordlist_id      TEXT NOT NULL REFERENCES wordlists(id),
  wordlist_version TEXT NOT NULL,
  wordlist_hash    TEXT NOT NULL,
  scan_profile     TEXT NOT NULL,
  requested_count  INTEGER NOT NULL,
  completed_count  INTEGER NOT NULL DEFAULT 0,
  skipped_count    INTEGER NOT NULL DEFAULT 0,
  hit_count        INTEGER NOT NULL DEFAULT 0,
  stop_reason      TEXT,
  approval_id      TEXT,
  started_at       TEXT NOT NULL,
  finished_at      TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wordlist_runs_target ON wordlist_runs (target_id, started_at DESC);

CREATE TABLE IF NOT EXISTS reports (
  id               TEXT PRIMARY KEY,
  report_ref       TEXT NOT NULL UNIQUE,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  scan_id          TEXT REFERENCES scans(id) ON DELETE SET NULL,
  report_type      TEXT NOT NULL
                   CHECK (report_type IN ('internal_pentest','executive_summary','technical_appendix','asset_inventory','change_timeline','vulnerability_summary','hackerone','bugcrowd','retest')),
  format           TEXT NOT NULL CHECK (format IN ('markdown','json','pdf')),
  title            TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','generating','ready','failed','expired','deleted')),
  r2_key           TEXT,
  content_hash     TEXT,
  size_bytes       INTEGER,
  encrypted        INTEGER NOT NULL DEFAULT 1 CHECK (encrypted IN (0,1)),
  generated_by     TEXT,
  renderer         TEXT,
  finding_ids      TEXT NOT NULL DEFAULT '[]',
  change_ids       TEXT NOT NULL DEFAULT '[]',
  redacted         INTEGER NOT NULL DEFAULT 1 CHECK (redacted IN (0,1)),
  includes_secrets INTEGER NOT NULL DEFAULT 0 CHECK (includes_secrets IN (0,1)),
  authorization_period TEXT,
  methodology      TEXT,
  limitations      TEXT,
  disclosure_warning TEXT,
  disclaimer_accepted_by TEXT,
  disclosure_state TEXT NOT NULL DEFAULT 'internal_only'
                   CHECK (disclosure_state IN ('internal_only','pending_approval','approved_for_share','shared')),
  share_approved_by TEXT,
  share_approved_at TEXT,
  error_message    TEXT,
  expires_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_target ON reports (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status, created_at);


CREATE TABLE IF NOT EXISTS report_downloads (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  report_id        TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  issued_to        TEXT NOT NULL REFERENCES users(id),
  token_hash       TEXT NOT NULL UNIQUE,
  expires_at       TEXT NOT NULL,
  consumed_at      TEXT,
  revoked_at       TEXT,
  source_ip        TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_report_downloads_report ON report_downloads (report_id, expires_at);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scope            TEXT NOT NULL,
  idempotency_key  TEXT NOT NULL,
  request_hash     TEXT NOT NULL,
  response_status  INTEGER,
  response_body    TEXT,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  UNIQUE (organization_id, scope, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_keys (expires_at);

CREATE TABLE IF NOT EXISTS webhook_receipts (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT,
  source           TEXT NOT NULL,
  nonce            TEXT NOT NULL,
  request_hash     TEXT NOT NULL,
  payload_hash     TEXT NOT NULL,
  signature_state  TEXT NOT NULL CHECK (signature_state IN ('valid','invalid','missing')),
  received_at      TEXT NOT NULL,
  processed_at     TEXT,
  result           TEXT,
  UNIQUE (source, nonce)
);

CREATE INDEX IF NOT EXISTS idx_webhook_receipts_time ON webhook_receipts (received_at);

CREATE TABLE IF NOT EXISTS telegram_updates (
  update_id        INTEGER PRIMARY KEY,
  chat_id          TEXT NOT NULL,
  user_id          TEXT,
  command          TEXT,
  handled_at       TEXT NOT NULL,
  result           TEXT
);

CREATE INDEX IF NOT EXISTS idx_telegram_updates_time ON telegram_updates (handled_at);

CREATE TABLE IF NOT EXISTS dead_letters (
  id               TEXT PRIMARY KEY,
  queue            TEXT NOT NULL,
  message_id       TEXT,
  organization_id  TEXT,
  target_id        TEXT,
  job_id           TEXT,
  attempts         INTEGER NOT NULL,
  payload_redacted TEXT NOT NULL,
  error_message    TEXT,
  created_at       TEXT NOT NULL,
  replayed_at      TEXT,
  replayed_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_dead_letters_queue ON dead_letters (queue, created_at DESC);

CREATE TABLE IF NOT EXISTS suppression_rules (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  change_type      TEXT NOT NULL,
  entity_pattern   TEXT NOT NULL,
  reason           TEXT NOT NULL,
  created_by       TEXT NOT NULL REFERENCES users(id),
  expires_at       TEXT,
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suppression_lookup ON suppression_rules (organization_id, target_id, change_type, enabled);

CREATE TABLE IF NOT EXISTS providers (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  adapter          TEXT NOT NULL,
  kind             TEXT NOT NULL
                   CHECK (kind IN ('certificate_transparency','dns','subdomain','http','service','javascript','api','technology','vulnerability','cve','cloud','notification','repository','screenshot')),
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  requires_runner  INTEGER NOT NULL DEFAULT 0 CHECK (requires_runner IN (0,1)),
  requires_credentials INTEGER NOT NULL DEFAULT 0 CHECK (requires_credentials IN (0,1)),
  secret_ref       TEXT,
  rate_limit_per_minute INTEGER NOT NULL DEFAULT 30,
  max_response_bytes INTEGER NOT NULL DEFAULT 5242880,
  timeout_ms       INTEGER NOT NULL DEFAULT 10000,
  priority         INTEGER NOT NULL DEFAULT 10,
  config_json      TEXT NOT NULL DEFAULT '{}',
  health_state     TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (organization_id, adapter)
);

CREATE INDEX IF NOT EXISTS idx_providers_kind ON providers (organization_id, kind, enabled);
