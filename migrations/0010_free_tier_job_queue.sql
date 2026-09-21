-- 0010_free_tier_job_queue.sql
-- Free-tier replacements for Cloudflare Queues + Durable Objects.
-- All three tables are D1-only and run on the free plan.

-- ---------------------------------------------------------------------------
-- job_queue — replaces Cloudflare Queues (SCAN_QUEUE, NOTIFY_QUEUE, REPORT_QUEUE)
-- ---------------------------------------------------------------------------
-- Producers INSERT rows here. The single cron trigger polls every 5 minutes,
-- claims pending jobs via a SELECT-then-UPDATE pattern, runs them via
-- ctx.waitUntil(), and marks them completed/failed.
--
-- Status flow:
--   pending → running → completed (success)
--                     ↘ failed → pending (retry, with exponential backoff via run_after)
--                              ↘ dead_letter (max_attempts exceeded)
--                     ↘ cancelled (operator-cancelled)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS job_queue (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL CHECK (kind IN ('scan','notification','report')),
  payload_json    TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','failed','cancelled','dead_letter')),
  priority        INTEGER NOT NULL DEFAULT 0,
  attempts        INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 3,
  run_after       TEXT NOT NULL,        -- ISO timestamp: earliest the job may run (jitter/backoff)
  locked_until    TEXT NOT NULL,        -- ISO timestamp: claimed by a worker until this time
  created_at      TEXT NOT NULL,
  started_at      TEXT,
  completed_at    TEXT,
  last_error      TEXT,
  dedup_key        TEXT                 -- optional: prevents duplicate jobs (UNIQUE on pending/running)
);

CREATE INDEX IF NOT EXISTS idx_job_queue_status_kind_run ON job_queue (status, kind, run_after, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_job_queue_dedup ON job_queue (dedup_key, status);
CREATE INDEX IF NOT EXISTS idx_job_queue_target ON job_queue (kind, status, json_extract(payload_json, '$.target_id'));
CREATE INDEX IF NOT EXISTS idx_job_queue_created ON job_queue (created_at);  -- for purge

-- ---------------------------------------------------------------------------
-- emergency_stop_state — replaces EmergencyStopDO Durable Object
-- ---------------------------------------------------------------------------
-- Single row per (scope, id). When a row exists and is active and not
-- expired, scanning is blocked. Auto-expired lazily on read.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS emergency_stop_state (
  scope          TEXT NOT NULL CHECK (scope IN ('global','organization','target','job')),
  id             TEXT NOT NULL DEFAULT 'GLOBAL',  -- 'GLOBAL' for global, otherwise the org/target/job ID
  active         INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0,1)),
  reason         TEXT,
  activated_by   TEXT,
  activated_at   TEXT NOT NULL,
  expires_at     TEXT,                  -- NULL = never expires
  PRIMARY KEY (scope, id)
);

-- ---------------------------------------------------------------------------
-- rate_limits_v2 — replaces RateLimiterDO Durable Object
-- ---------------------------------------------------------------------------
-- One row per rate-limit key (e.g. "target:TGT_abc" or "provider:crtsh").
-- Stores recent hit timestamps as JSON array + backoff state.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rate_limits_v2 (
  key                TEXT PRIMARY KEY,
  hits_json          TEXT NOT NULL DEFAULT '[]',     -- JSON array of ms timestamps (last 60s)
  backoff_until      INTEGER NOT NULL DEFAULT 0,    -- ms epoch
  consecutive_errors INTEGER NOT NULL DEFAULT 0,
  updated_at         TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- locks — replaces LockDO Durable Object
-- ---------------------------------------------------------------------------
-- One row per lock key (e.g. "target:TGT_abc"). Auto-expires when
-- locked_until passes. Acquired via INSERT ... ON CONFLICT DO NOTHING
-- (atomic on SQLite).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS locks (
  key            TEXT PRIMARY KEY,
  holder_id      TEXT NOT NULL,
  locked_until   INTEGER NOT NULL,                  -- ms epoch
  acquired_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_locks_expiry ON locks (locked_until);
