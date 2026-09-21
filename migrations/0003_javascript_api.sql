-- ===========================================================================
-- Watchtower migration 0003 - JavaScript monitoring and API endpoint inventory
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS javascript_files (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,
  url_canonical    TEXT NOT NULL,
  hostname         TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed','unreachable','out_of_scope')),
  http_status      INTEGER,
  content_type     TEXT,
  content_length   INTEGER,
  etag             TEXT,
  last_modified    TEXT,
  content_hash     TEXT,
  normalized_hash  TEXT,
  r2_key           TEXT,
  r2_key_previous  TEXT,
  has_source_map   INTEGER NOT NULL DEFAULT 0 CHECK (has_source_map IN (0,1)),
  source_map_url   TEXT,
  discovered_via   TEXT NOT NULL,
  extraction_mode  TEXT NOT NULL DEFAULT 'regex'
                   CHECK (extraction_mode IN ('parser','regex','hybrid')),
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  is_first_party   INTEGER NOT NULL DEFAULT 1 CHECK (is_first_party IN (0,1)),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_js_files_asset ON javascript_files (asset_id, status);
CREATE INDEX IF NOT EXISTS idx_js_files_hash ON javascript_files (content_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_js_files_unique ON javascript_files (asset_id, url_canonical);

CREATE TABLE IF NOT EXISTS javascript_diffs (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  file_id          TEXT NOT NULL REFERENCES javascript_files(id) ON DELETE CASCADE,
  job_id           TEXT,
  change_kind      TEXT NOT NULL
                   CHECK (change_kind IN ('added','removed','modified','unchanged')),
  before_hash      TEXT,
  after_hash       TEXT,
  before_size      INTEGER,
  after_size       INTEGER,
  added_lines      INTEGER NOT NULL DEFAULT 0,
  removed_lines    INTEGER NOT NULL DEFAULT 0,
  similarity       REAL,
  significance     TEXT NOT NULL DEFAULT 'low'
                   CHECK (significance IN ('informational','low','medium','high','critical')),
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  diff_redacted    TEXT,
  diff_truncated   INTEGER NOT NULL DEFAULT 0 CHECK (diff_truncated IN (0,1)),
  sensitive_areas  TEXT NOT NULL DEFAULT '[]',
  endpoints_added  TEXT NOT NULL DEFAULT '[]',
  endpoints_removed TEXT NOT NULL DEFAULT '[]',
  review_state     TEXT NOT NULL DEFAULT 'unreviewed'
                   CHECK (review_state IN ('unreviewed','expected','suspicious','confirmed_change','false_positive')),
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_js_diffs_file ON javascript_diffs (file_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_js_diffs_target ON javascript_diffs (target_id, created_at DESC);

CREATE TABLE IF NOT EXISTS api_endpoints (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  base_url         TEXT NOT NULL,
  method           TEXT NOT NULL DEFAULT 'GET'
                   CHECK (method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','WEBSOCKET','GRAPHQL')),
  path             TEXT NOT NULL,
  parameters       TEXT NOT NULL DEFAULT '[]',
  path_template    TEXT,
  api_version      TEXT,
  content_type     TEXT,
  auth_required    TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (auth_required IN ('unknown','none','optional','required','oauth','apikey')),
  discovery_source TEXT NOT NULL,
  spec_source      TEXT,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed','unverified')),
  state_changing   INTEGER NOT NULL DEFAULT 0 CHECK (state_changing IN (0,1)),
  tested           INTEGER NOT NULL DEFAULT 0 CHECK (tested IN (0,1)),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_asset ON api_endpoints (asset_id, status);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_target ON api_endpoints (target_id, method);

CREATE TABLE IF NOT EXISTS javascript_secrets (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  file_id          TEXT REFERENCES javascript_files(id) ON DELETE CASCADE,
  finding_id       TEXT,
  secret_type      TEXT NOT NULL,
  value_fingerprint TEXT NOT NULL,
  value_preview_redacted TEXT NOT NULL,
  location_line    INTEGER,
  location_column  INTEGER,
  context_redacted TEXT,
  entropy          REAL,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL DEFAULT 'unverified'
                   CHECK (verification_state IN ('unverified','likely_false_positive','likely_real','human_confirmed','not_testable')),
  tested_by_platform INTEGER NOT NULL DEFAULT 0 CHECK (tested_by_platform IN (0,1)),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (asset_id, value_fingerprint, secret_type)
);

CREATE INDEX IF NOT EXISTS idx_js_secrets_target ON javascript_secrets (target_id, verification_state);
CREATE INDEX IF NOT EXISTS idx_js_secrets_finding ON javascript_secrets (finding_id);

