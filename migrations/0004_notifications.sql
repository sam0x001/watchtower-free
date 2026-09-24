-- ===========================================================================
-- Watchtower migration 0004 - notifications (Telegram delivery log + dedup)
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS notifications (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL DEFAULT 'default',
  target_id       TEXT,
  finding_id      TEXT,
  channel         TEXT NOT NULL DEFAULT 'telegram',
  destination     TEXT NOT NULL,
  alert_type      TEXT NOT NULL,
  severity        TEXT NOT NULL DEFAULT 'informational'
                  CHECK (severity IN ('informational','low','medium','high','critical')),
  title           TEXT NOT NULL,
  body_redacted   TEXT NOT NULL,
  dedupe_key      TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','sent','failed','deduplicated')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  sent_at         TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_dedupe ON notifications (dedupe_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_target ON notifications (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications (created_at);
