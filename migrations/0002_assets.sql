-- ===========================================================================
-- Watchtower migration 0002 - discovered assets and their observations
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_type       TEXT NOT NULL
                   CHECK (asset_type IN ('domain','subdomain','ip','url')),
  identifier       TEXT NOT NULL,
  display_name     TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed','unreachable')),
  in_scope         INTEGER NOT NULL DEFAULT 0 CHECK (in_scope IN (0,1)),
  scope_state      TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (scope_state IN ('allowed','denied','unknown')),
  source           TEXT NOT NULL,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  last_probed      TEXT,
  removed_at       TEXT,
  removed_reason   TEXT,
  attributes_json  TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets (target_id, asset_type, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_unique ON assets (target_id, asset_type, identifier);

CREATE TABLE IF NOT EXISTS dns_records (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE CASCADE,
  hostname         TEXT NOT NULL,
  record_type      TEXT NOT NULL
                   CHECK (record_type IN ('A','AAAA','CNAME','MX','NS','TXT','SOA','CAA','SRV','HTTPS','PTR')),
  value            TEXT NOT NULL,
  priority         INTEGER,
  ttl              INTEGER,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  is_current       INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0,1)),
  removed_at       TEXT,
  fingerprint      TEXT NOT NULL,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_records_asset ON dns_records (asset_id, is_current);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_unique ON dns_records (asset_id, fingerprint);

CREATE TABLE IF NOT EXISTS certificates (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE SET NULL,
  source           TEXT NOT NULL,
  serial_number    TEXT,
  issuer_cn        TEXT,
  not_before       TEXT,
  not_after        TEXT,
  dns_names        TEXT NOT NULL DEFAULT '[]',
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','expired','disappeared')),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  disappeared_at   TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_target ON certificates (target_id, status);

CREATE TABLE IF NOT EXISTS services (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  hostname         TEXT NOT NULL,
  port             INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
  transport        TEXT NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp','udp')),
  protocol         TEXT,
  service_name     TEXT,
  banner_redacted  TEXT,
  tls_json         TEXT NOT NULL DEFAULT '{}',
  state            TEXT NOT NULL DEFAULT 'open'
                   CHECK (state IN ('open','closed','filtered','unknown')),
  discovery_method TEXT NOT NULL,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_asset ON services (asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_services_unique ON services (asset_id, port, transport);

CREATE TABLE IF NOT EXISTS technologies (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  category         TEXT NOT NULL,
  version          TEXT,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  detection_method TEXT NOT NULL,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_technologies_asset ON technologies (asset_id);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies (name, version);

-- JavaScript files discovered on probed hosts, tracked by content hash so a
-- redeploy surfaces as a change alert.
CREATE TABLE IF NOT EXISTS javascript_files (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,
  url_canonical    TEXT NOT NULL,
  hostname         TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed','unreachable')),
  content_type     TEXT,
  content_length   INTEGER,
  etag             TEXT,
  last_modified    TEXT,
  content_hash     TEXT,
  discovered_via   TEXT NOT NULL,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_js_files_asset ON javascript_files (asset_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_js_files_unique ON javascript_files (asset_id, url_canonical);

-- API endpoints extracted from JavaScript bodies (observations only).
CREATE TABLE IF NOT EXISTS api_endpoints (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL DEFAULT 'default',
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  base_url         TEXT NOT NULL DEFAULT '',
  method           TEXT NOT NULL DEFAULT 'GET',
  path             TEXT NOT NULL,
  parameters       TEXT NOT NULL DEFAULT '[]',
  discovery_source TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed')),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_asset ON api_endpoints (asset_id, status);
