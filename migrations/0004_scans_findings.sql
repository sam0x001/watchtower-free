-- ===========================================================================
-- Watchtower migration 0004 - scans, jobs, findings and evidence
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  -- Full scope snapshot at scan start. Guarantees a scan is auditable even if
  -- scope is edited afterwards.
  scope_snapshot   TEXT NOT NULL,
  scope_hash       TEXT NOT NULL,
  profile          TEXT NOT NULL,
  mode             TEXT NOT NULL CHECK (mode IN ('passive','low_impact_active','intrusive')),
  trigger          TEXT NOT NULL CHECK (trigger IN ('manual','schedule','cron','api','retest')),
  status           TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','validating','running','completed','failed','cancelled','scope_denied','stopped')),
  requested_by     TEXT,
  started_at       TEXT,
  finished_at      TEXT,
  stop_reason      TEXT,
  approval_id      TEXT,
  correlation_id   TEXT,
  assets_seen      INTEGER NOT NULL DEFAULT 0,
  changes_detected INTEGER NOT NULL DEFAULT 0,
  findings_created INTEGER NOT NULL DEFAULT 0,
  errors_json      TEXT NOT NULL DEFAULT '[]',
  provider_stats   TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans (organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  job_type         TEXT NOT NULL,
  adapter          TEXT NOT NULL,
  runner_required  INTEGER NOT NULL DEFAULT 0 CHECK (runner_required IN (0,1)),
  runner_id        TEXT REFERENCES runners(id),
  priority         INTEGER NOT NULL DEFAULT 5,
  status           TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','awaiting_approval','dispatched','running','completed','failed','cancelled','stopped','timeout','rejected')),
  attempt          INTEGER NOT NULL DEFAULT 0,
  max_attempts     INTEGER NOT NULL DEFAULT 3,
  -- Allowlisted, normalized job input. Never raw user text.
  payload          TEXT NOT NULL DEFAULT '{}',
  payload_hash     TEXT NOT NULL,
  -- Denormalized target set so scope can be re-validated at execution time.
  requested_targets TEXT NOT NULL DEFAULT '[]',
  scheduled_for    TEXT NOT NULL,
  dispatched_at    TEXT,
  started_at       TEXT,
  finished_at      TEXT,
  heartbeat_at     TEXT,
  timeout_at       TEXT NOT NULL,
  -- Encrypted reference to results; large results live in R2.
  result_ref       TEXT,
  result_hash      TEXT,
  result_summary   TEXT NOT NULL DEFAULT '{}',
  error_code       TEXT,
  error_message    TEXT,
  backoff_until    TEXT,
  cancelled_by     TEXT,
  cancel_reason    TEXT,
  idempotency_key  TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_scan ON scan_jobs (scan_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_dispatch ON scan_jobs (status, scheduled_for, priority);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_runner ON scan_jobs (runner_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_timeout ON scan_jobs (status, timeout_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_idem ON scan_jobs (organization_id, idempotency_key);

CREATE TABLE IF NOT EXISTS scan_results (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  job_id           TEXT REFERENCES scan_jobs(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE SET NULL,
  adapter          TEXT NOT NULL,
  result_type      TEXT NOT NULL,
  summary          TEXT NOT NULL DEFAULT '{}',
  item_count       INTEGER NOT NULL DEFAULT 0,
  payload_ref      TEXT,
  payload_hash     TEXT,
  truncated        INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  duration_ms      INTEGER,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results (scan_id, adapter);
CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results (target_id, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
  id                 TEXT PRIMARY KEY,
  finding_ref        TEXT NOT NULL UNIQUE,
  organization_id    TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id          TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id           TEXT REFERENCES assets(id) ON DELETE SET NULL,
  scan_id            TEXT REFERENCES scans(id) ON DELETE SET NULL,
  job_id             TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  finding_type       TEXT NOT NULL,
  title              TEXT NOT NULL,
  summary            TEXT NOT NULL,
  technical_detail   TEXT,
  business_impact    TEXT,
  severity           TEXT NOT NULL DEFAULT 'informational'
                     CHECK (severity IN ('informational','low','medium','high','critical')),
  severity_score     REAL,
  priority_score     REAL,
  cvss_score         REAL,
  cvss_vector        TEXT,
  cvss_version       TEXT,
  epss_score         REAL,
  epss_percentile    REAL,
  kev_listed         INTEGER NOT NULL DEFAULT 0 CHECK (kev_listed IN (0,1)),
  cwe_id             TEXT,
  cve_id             TEXT,
  owasp_category     TEXT,
  owasp_api_category TEXT,
  affected_asset     TEXT NOT NULL,
  affected_url       TEXT,
  affected_port      INTEGER,
  affected_parameter TEXT,
  detection_source   TEXT NOT NULL,
  detection_method   TEXT NOT NULL,
  confidence         REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL DEFAULT 'detected'
                     CHECK (verification_state IN ('detected','suspected','verified','confirmed_by_human','false_positive','rejected')),
  status             TEXT NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','triaged','in_progress','resolved','closed','suppressed','duplicate')),
  scope_validation   TEXT NOT NULL DEFAULT 'pending'
                     CHECK (scope_validation IN ('pending','in_scope','out_of_scope','expired','denied')),
  in_scope           INTEGER NOT NULL DEFAULT 0 CHECK (in_scope IN (0,1)),
  assigned_user_id   TEXT REFERENCES users(id),
  remediation        TEXT,
  remediation_state  TEXT NOT NULL DEFAULT 'unaddressed'
                     CHECK (remediation_state IN ('unaddressed','in_progress','fixed','wont_fix','risk_accepted')),
  retest_status      TEXT NOT NULL DEFAULT 'not_retested'
                     CHECK (retest_status IN ('not_retested','scheduled','passed','failed','blocked')),
  retested_at        TEXT,
  duplicate_of       TEXT REFERENCES findings(id),
  parent_finding_id  TEXT REFERENCES findings(id),
  attack_chain_id    TEXT,
  related_finding_ids TEXT NOT NULL DEFAULT '[]',
  duplicate_group    TEXT,
  evidence_hashes    TEXT NOT NULL DEFAULT '[]',
  metadata_json      TEXT NOT NULL DEFAULT '{}',
  fingerprint        TEXT NOT NULL,
  alert_sent_at      TEXT,
  suppressed_until   TEXT,
  suppressed_by      TEXT,
  suppress_reason    TEXT,
  first_seen         TEXT NOT NULL,
  last_seen          TEXT NOT NULL,
  resolved_at        TEXT,
  closed_at          TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (organization_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_assignee ON findings (assigned_user_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings (cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_verification ON findings (verification_state, severity);
CREATE INDEX IF NOT EXISTS idx_findings_dup ON findings (duplicate_of);

CREATE TABLE IF NOT EXISTS finding_evidence (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  finding_id       TEXT REFERENCES findings(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE SET NULL,
  change_id        TEXT,
  evidence_type    TEXT NOT NULL
                   CHECK (evidence_type IN ('http_request','http_response','headers','body_excerpt','screenshot','dom_snapshot','tls_certificate','diff','scan_output','secret_candidate','before_snapshot','after_snapshot','timeline')),
  r2_key           TEXT NOT NULL,
  content_hash     TEXT NOT NULL,
  encrypted        INTEGER NOT NULL DEFAULT 1 CHECK (encrypted IN (0,1)),
  encryption_alg   TEXT NOT NULL DEFAULT 'AES-256-GCM',
  key_version      TEXT NOT NULL DEFAULT 'v1',
  content_type     TEXT,
  size_bytes       INTEGER NOT NULL,
  redacted         INTEGER NOT NULL DEFAULT 1 CHECK (redacted IN (0,1)),
  redaction_notes  TEXT,
  captured_by      TEXT NOT NULL,
  capture_method   TEXT NOT NULL,
  tool_name        TEXT,
  tool_version     TEXT,
  scan_profile     TEXT,
  request_id       TEXT,
  source_ip        TEXT,
  captured_at      TEXT NOT NULL,
  captured_timezone TEXT NOT NULL DEFAULT 'UTC',
  custody_chain    TEXT NOT NULL DEFAULT '[]',
  verified_at      TEXT,
  retention_until  TEXT,
  deleted_at       TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_target ON finding_evidence (target_id, evidence_type);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_retention ON finding_evidence (retention_until, deleted_at);

CREATE TABLE IF NOT EXISTS finding_comments (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id       TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  author_user_id   TEXT REFERENCES users(id),
  author_kind      TEXT NOT NULL CHECK (author_kind IN ('user','system','runner','integration')),
  body             TEXT NOT NULL,
  body_format      TEXT NOT NULL DEFAULT 'markdown' CHECK (body_format IN ('markdown','plain')),
  is_internal      INTEGER NOT NULL DEFAULT 1 CHECK (is_internal IN (0,1)),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments (finding_id, created_at);

CREATE TABLE IF NOT EXISTS finding_history (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id       TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  actor_user_id    TEXT,
  actor_kind       TEXT NOT NULL CHECK (actor_kind IN ('user','system','runner','integration')),
  action           TEXT NOT NULL,
  from_value       TEXT,
  to_value         TEXT,
  note             TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_history_finding ON finding_history (finding_id, created_at DESC);

