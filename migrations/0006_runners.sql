-- ===========================================================================
-- Watchtower migration 0006 - external scanner runners
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runners (
  id                   TEXT PRIMARY KEY,
  organization_id      TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  name                 TEXT NOT NULL,
  kind                 TEXT NOT NULL
                       CHECK (kind IN ('container','github_action','cloud_run','fly_io','aws_batch','lambda_container','self_hosted','browser_runner')),
  endpoint_url         TEXT NOT NULL,
  public_key           TEXT NOT NULL,
  token_hash           TEXT NOT NULL,
  token_prefix         TEXT NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','active','degraded','revoked','unhealthy')),
  capabilities         TEXT NOT NULL DEFAULT '[]',
  max_concurrency      INTEGER NOT NULL DEFAULT 2,
  current_jobs         INTEGER NOT NULL DEFAULT 0,
  allowed_egress_json  TEXT NOT NULL DEFAULT '[]',
  cpu_limit            TEXT,
  memory_limit_mb      INTEGER,
  timeout_seconds      INTEGER NOT NULL DEFAULT 900,
  max_output_bytes     INTEGER NOT NULL DEFAULT 5242880,
  last_heartbeat_at    TEXT,
  last_seen_ip         TEXT,
  health_state         TEXT NOT NULL DEFAULT '{}',
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  revoked_at           TEXT,
  revoked_by           TEXT,
  revoked_reason       TEXT,
  created_by           TEXT REFERENCES users(id),
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runners_status ON runners (status, last_heartbeat_at);
CREATE INDEX IF NOT EXISTS idx_runners_org ON runners (organization_id, status);

CREATE TABLE IF NOT EXISTS runner_jobs (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  job_id           TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  runner_id        TEXT NOT NULL REFERENCES runners(id),
  tool             TEXT NOT NULL,
  argv_json        TEXT NOT NULL,
  scope_snapshot   TEXT NOT NULL,
  scope_hash       TEXT NOT NULL,
  payload_json     TEXT NOT NULL,
  payload_hash     TEXT NOT NULL,
  signature        TEXT NOT NULL,
  nonce            TEXT NOT NULL,
  token_hash       TEXT NOT NULL,
  token_expires_at TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'issued'
                   CHECK (status IN ('issued','acknowledged','running','completed','failed','expired','revoked')),
  used_at          TEXT,
  result_signature TEXT,
  result_hash      TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (job_id, runner_id)
);

CREATE INDEX IF NOT EXISTS idx_runner_jobs_runner ON runner_jobs (runner_id, status);
CREATE INDEX IF NOT EXISTS idx_runner_jobs_expiry ON runner_jobs (status, token_expires_at);
