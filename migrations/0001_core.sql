-- ===========================================================================
-- Watchtower migration 0001 - core: targets, scope (allow + deny), allowed
-- Telegram users, distributed locks.
--
-- Schema note: this is a multi-file migration set on purpose (0001 core,
-- 0002 assets, 0003 scans, 0004 notifications) so a failure in one area can
-- be diagnosed and re-applied independently.
-- ===========================================================================
PRAGMA foreign_keys = ON;

-- Monitored targets. A target is a root domain (e.g. example.com); adding
-- `*.example.com` and `example.com` are equivalent — every subdomain is
-- in scope unless explicitly excluded via the `scopes` denylist.
CREATE TABLE IF NOT EXISTS targets (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  organization_id TEXT NOT NULL DEFAULT 'default',
  status          TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','paused')),
  paused_at       TEXT,
  created_by      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_status ON targets (status);

-- Scope entries. Allowlist row: the target root (scope_type 'domain').
-- Denylist rows (is_denylist = 1): excluded subdomains / paths. Deny beats
-- allow in src/scope/match.ts.
CREATE TABLE IF NOT EXISTS scopes (
  id            TEXT PRIMARY KEY,
  target_id     TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_type    TEXT NOT NULL
                CHECK (scope_type IN ('domain','wildcard_domain','ip','cidr','url','api')),
  value         TEXT NOT NULL,
  display_value TEXT NOT NULL,
  is_denylist   INTEGER NOT NULL DEFAULT 0 CHECK (is_denylist IN (0,1)),
  status        TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','removed')),
  created_by    TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  UNIQUE (target_id, value)
);

CREATE INDEX IF NOT EXISTS idx_scopes_target ON scopes (target_id, status);

-- Telegram users allowed to talk to the bot. Seeded from the
-- AUTHORIZED_TELEGRAM_IDS env var on first boot; extended with /allow.
CREATE TABLE IF NOT EXISTS allowed_users (
  telegram_id TEXT PRIMARY KEY,
  added_by    TEXT,
  created_at  TEXT NOT NULL
);

-- Distributed lock (per-target scan serialization). Auto-expires via
-- locked_until (ms epoch).
CREATE TABLE IF NOT EXISTS locks (
  key          TEXT PRIMARY KEY,
  holder_id    TEXT NOT NULL,
  locked_until INTEGER NOT NULL,
  acquired_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_locks_expiry ON locks (locked_until);
