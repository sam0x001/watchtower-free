-- ===========================================================================
-- Watchtower migration 0001 - core tenancy, authorization, scope, audit
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  slug              TEXT NOT NULL UNIQUE,
  program_type      TEXT NOT NULL DEFAULT 'internal_pentest'
                    CHECK (program_type IN ('bug_bounty','internal_pentest','vendor_disclosure','red_team','research')),
  program_url       TEXT,
  emergency_stop    INTEGER NOT NULL DEFAULT 0 CHECK (emergency_stop IN (0,1)),
  emergency_stop_at TEXT,
  emergency_stop_by TEXT,
  emergency_stop_reason TEXT,
  passive_only      INTEGER NOT NULL DEFAULT 1 CHECK (passive_only IN (0,1)),
  settings_json     TEXT NOT NULL DEFAULT '{}',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id                    TEXT PRIMARY KEY,
  telegram_user_id      TEXT UNIQUE,
  telegram_username     TEXT,
  email                 TEXT,
  display_name          TEXT NOT NULL,
  telegram_verified_at  TEXT,
  telegram_verify_token TEXT,
  is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  last_seen_at          TEXT,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_telegram_user_id ON users (telegram_user_id);

CREATE TABLE IF NOT EXISTS roles (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE
                CHECK (name IN ('owner','administrator','analyst','viewer','external_reviewer')),
  description   TEXT NOT NULL,
  rank          INTEGER NOT NULL,
  capabilities  TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id          TEXT NOT NULL REFERENCES roles(id),
  status           TEXT NOT NULL DEFAULT 'invited'
                   CHECK (status IN ('invited','active','suspended','removed')),
  invited_by       TEXT REFERENCES users(id),
  invited_at       TEXT,
  accepted_at      TEXT,
  mfa_required     INTEGER NOT NULL DEFAULT 0 CHECK (mfa_required IN (0,1)),
  allowed_chat_ids TEXT NOT NULL DEFAULT '[]',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships (user_id, status);

CREATE TABLE IF NOT EXISTS api_tokens (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
  runner_id        TEXT,
  name             TEXT NOT NULL,
  token_hash       TEXT NOT NULL UNIQUE,
  token_prefix     TEXT NOT NULL,
  scopes           TEXT NOT NULL DEFAULT '[]',
  expires_at       TEXT NOT NULL,
  last_used_at     TEXT,
  revoked_at       TEXT,
  revoked_by       TEXT,
  created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
  id                   TEXT PRIMARY KEY,
  organization_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                 TEXT NOT NULL,
  description          TEXT,
  program_handle       TEXT,
  criticality          TEXT NOT NULL DEFAULT 'medium'
                       CHECK (criticality IN ('low','medium','high','critical')),
  data_sensitivity     TEXT NOT NULL DEFAULT 'internal'
                       CHECK (data_sensitivity IN ('public','internal','confidential','regulated')),
  internet_exposed     INTEGER NOT NULL DEFAULT 1 CHECK (internet_exposed IN (0,1)),
  status               TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','paused','expired','archived')),
  paused_at            TEXT,
  paused_by            TEXT,
  authorization_status TEXT NOT NULL DEFAULT 'pending'
                       CHECK (authorization_status IN ('pending','confirmed','revoked','expired')),
  authorization_type   TEXT CHECK (authorization_type IN
                       ('written_permission','bug_bounty_program','internal_mandate','vendor_contract')),
  authorized_by_name   TEXT,
  authorized_by_email  TEXT,
  authorization_ref    TEXT,
  authorization_note   TEXT,
  authorization_hash   TEXT,
  authorization_confirmed_at TEXT,
  authorization_confirmed_by TEXT REFERENCES users(id),
  valid_from           TEXT NOT NULL,
  valid_until          TEXT NOT NULL,
  passive_only         INTEGER NOT NULL DEFAULT 1 CHECK (passive_only IN (0,1)),
  low_impact_active    INTEGER NOT NULL DEFAULT 0 CHECK (low_impact_active IN (0,1)),
  intrusive_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (intrusive_enabled IN (0,1)),
  human_approval_required INTEGER NOT NULL DEFAULT 1 CHECK (human_approval_required IN (0,1)),
  max_requests_per_minute INTEGER NOT NULL DEFAULT 60,
  max_concurrent_jobs  INTEGER NOT NULL DEFAULT 1,
  scan_profile         TEXT NOT NULL DEFAULT 'passive-only',
  created_by           TEXT NOT NULL REFERENCES users(id),
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_org ON targets (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_targets_validity ON targets (valid_until, status);

CREATE TABLE IF NOT EXISTS scopes (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_type       TEXT NOT NULL
                   CHECK (scope_type IN ('domain','wildcard_domain','ip','cidr','url','api','repository','cloud_account','mobile_app')),
  value            TEXT NOT NULL,
  display_value    TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','paused','expired','removed')),
  is_primary       INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
  is_denylist      INTEGER NOT NULL DEFAULT 0 CHECK (is_denylist IN (0,1)),
  include_subdomains INTEGER NOT NULL DEFAULT 1 CHECK (include_subdomains IN (0,1)),
  cloud_account_id TEXT,
  notes            TEXT,
  valid_from       TEXT NOT NULL,
  valid_until      TEXT NOT NULL,
  paused_at        TEXT,
  paused_by        TEXT,
  expired_at       TEXT,
  created_by       TEXT NOT NULL REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (target_id, scope_type, value)
);

CREATE INDEX IF NOT EXISTS idx_scopes_target ON scopes (target_id, status);
CREATE INDEX IF NOT EXISTS idx_scopes_value ON scopes (value);

CREATE TABLE IF NOT EXISTS scope_rules (
  id            TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scope_id      TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  rule_kind     TEXT NOT NULL
                CHECK (rule_kind IN ('port','path','asset_type','method','header','content_type','ip_range')),
  effect        TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  value         TEXT NOT NULL,
  value_end     TEXT,
  notes         TEXT,
  created_by    TEXT NOT NULL REFERENCES users(id),
  created_at    TEXT NOT NULL,
  UNIQUE (scope_id, rule_kind, effect, value)
);

CREATE INDEX IF NOT EXISTS idx_scope_rules_scope ON scope_rules (scope_id, rule_kind, effect);

CREATE TABLE IF NOT EXISTS program_rules (
  id                    TEXT PRIMARY KEY,
  organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id             TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  title                 TEXT NOT NULL,
  body                  TEXT NOT NULL,
  rule_type             TEXT NOT NULL
                        CHECK (rule_type IN ('testing_restriction','rate_limit','prohibited_action','reporting_requirement','disclosure','other')),
  enforce_no_dos        INTEGER NOT NULL DEFAULT 1 CHECK (enforce_no_dos IN (0,1)),
  enforce_no_automated_scanning INTEGER NOT NULL DEFAULT 0 CHECK (enforce_no_automated_scanning IN (0,1)),
  enforce_no_credential_attacks INTEGER NOT NULL DEFAULT 1 CHECK (enforce_no_credential_attacks IN (0,1)),
  enforce_no_social_engineering INTEGER NOT NULL DEFAULT 1 CHECK (enforce_no_social_engineering IN (0,1)),
  max_requests_per_minute INTEGER,
  allowed_hours_utc     TEXT,
  require_manual_approval INTEGER NOT NULL DEFAULT 1 CHECK (require_manual_approval IN (0,1)),
  created_by            TEXT NOT NULL REFERENCES users(id),
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_program_rules_target ON program_rules (target_id);

CREATE TABLE IF NOT EXISTS emergency_stops (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  job_id           TEXT,
  level            TEXT NOT NULL CHECK (level IN ('global','organization','target','job')),
  reason           TEXT NOT NULL,
  activated_by     TEXT NOT NULL,
  activated_at     TEXT NOT NULL,
  released_by      TEXT,
  released_at      TEXT,
  release_reason   TEXT,
  active           INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_emergency_stops_active ON emergency_stops (level, active);

CREATE TABLE IF NOT EXISTS audit_logs (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT,
  actor_user_id    TEXT,
  actor_kind       TEXT NOT NULL CHECK (actor_kind IN ('telegram','api','system','runner','webhook')),
  actor_identity   TEXT,
  command          TEXT NOT NULL,
  target_id        TEXT,
  scope_id         TEXT,
  job_id           TEXT,
  runner_id        TEXT,
  scanner          TEXT,
  arguments_redacted TEXT,
  result           TEXT NOT NULL CHECK (result IN ('success','denied','error','pending_approval')),
  result_detail    TEXT,
  approval_decision TEXT CHECK (approval_decision IN ('approved','rejected','auto','not_required')),
  approved_by      TEXT,
  request_metadata TEXT,
  correlation_id   TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_logs (correlation_id);

CREATE TABLE IF NOT EXISTS approvals (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  job_id           TEXT,
  requested_by     TEXT NOT NULL REFERENCES users(id),
  action           TEXT NOT NULL,
  rationale        TEXT NOT NULL,
  payload_redacted TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','approved','rejected','expired')),
  decided_by       TEXT REFERENCES users(id),
  decided_at       TEXT,
  decision_note    TEXT,
  expires_at       TEXT NOT NULL,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status, expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  id            TEXT PRIMARY KEY,
  organization_id TEXT,
  target_id     TEXT,
  bucket        TEXT NOT NULL,
  window_start  TEXT NOT NULL,
  window_seconds INTEGER NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  limit_value   INTEGER NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits (window_start);

CREATE TABLE IF NOT EXISTS retention_policies (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  data_class       TEXT NOT NULL
                   CHECK (data_class IN ('evidence','js_snapshot','report','audit','finding','scan_result','notification','wordlist')),
  retention_days   INTEGER NOT NULL,
  legal_hold       INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0,1)),
  purge_strategy   TEXT NOT NULL DEFAULT 'delete' CHECK (purge_strategy IN ('delete','anonymize')),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (organization_id, data_class)
);

