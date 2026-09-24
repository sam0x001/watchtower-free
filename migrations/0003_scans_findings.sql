-- ===========================================================================
-- Watchtower migration 0003 - scan tracking, job queue, findings
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
  id                TEXT PRIMARY KEY,
  organization_id   TEXT NOT NULL DEFAULT 'default',
  target_id         TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  trigger           TEXT NOT NULL CHECK (trigger IN ('manual','cron','continuation')),
  status            TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','completed','failed','cancelled')),
  requested_by      TEXT,
  started_at        TEXT,
  finished_at       TEXT,
  stop_reason       TEXT,
  errors_json       TEXT NOT NULL DEFAULT '[]',
  assets_seen       INTEGER NOT NULL DEFAULT 0,
  changes_detected INTEGER NOT NULL DEFAULT 0,
  findings_created  INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status, created_at);

-- D1-backed job queue (free tier: no Queues binding). The single cron trigger
-- polls this table every 5 minutes.
CREATE TABLE IF NOT EXISTS job_queue (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('scan','notification')),
  payload_json TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','running','completed','failed','cancelled','dead_letter')),
  priority     INTEGER NOT NULL DEFAULT 0,
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  run_after    TEXT NOT NULL,
  locked_until TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  started_at   TEXT,
  completed_at TEXT,
  last_error   TEXT,
  dedup_key    TEXT
);

CREATE INDEX IF NOT EXISTS idx_job_queue_status_kind_run ON job_queue (status, kind, run_after, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_job_queue_dedup ON job_queue (dedup_key, status);
CREATE INDEX IF NOT EXISTS idx_job_queue_created ON job_queue (created_at);

-- Findings: secret candidates detected in JavaScript, CVE matches against
-- fingerprinted technologies, and notable fuzzing results.
CREATE TABLE IF NOT EXISTS findings (
  id                 TEXT PRIMARY KEY,
  finding_ref        TEXT NOT NULL UNIQUE,
  organization_id    TEXT NOT NULL DEFAULT 'default',
  target_id          TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id           TEXT REFERENCES assets(id) ON DELETE SET NULL,
  finding_type       TEXT NOT NULL,
  title              TEXT NOT NULL,
  summary            TEXT NOT NULL,
  technical_detail   TEXT,
  severity           TEXT NOT NULL DEFAULT 'informational'
                     CHECK (severity IN ('informational','low','medium','high','critical')),
  cve_id             TEXT,
  cvss_score         REAL,
  affected_asset     TEXT NOT NULL DEFAULT '',
  affected_url       TEXT,
  detection_source   TEXT NOT NULL,
  detection_method   TEXT NOT NULL,
  confidence         REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL DEFAULT 'detected'
                     CHECK (verification_state IN ('detected','suspected','verified','false_positive')),
  status             TEXT NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','closed')),
  fingerprint        TEXT NOT NULL DEFAULT '',
  metadata_json      TEXT NOT NULL DEFAULT '{}',
  first_seen         TEXT NOT NULL,
  last_seen          TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings (cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (target_id, fingerprint);
