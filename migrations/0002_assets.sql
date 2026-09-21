-- ===========================================================================
-- Watchtower migration 0002 - discovered assets and their observations
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_id         TEXT REFERENCES scopes(id) ON DELETE SET NULL,
  asset_type       TEXT NOT NULL
                   CHECK (asset_type IN ('domain','subdomain','ip','cidr','url','api','repository','cloud_resource','mobile_app','service')),
  identifier       TEXT NOT NULL,
  display_name     TEXT NOT NULL,
  parent_asset_id  TEXT REFERENCES assets(id) ON DELETE SET NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','removed','unreachable','out_of_scope','archived')),
  in_scope         INTEGER NOT NULL DEFAULT 0 CHECK (in_scope IN (0,1)),
  scope_state      TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (scope_state IN ('allowed','denied','unknown','expired','paused')),
  source           TEXT NOT NULL,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  criticality      TEXT NOT NULL DEFAULT 'medium'
                   CHECK (criticality IN ('low','medium','high','critical')),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  removed_at       TEXT,
  removed_reason   TEXT,
  attributes_json  TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets (target_id, asset_type, status);
CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets (organization_id, identifier);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_unique ON assets (target_id, asset_type, identifier);

CREATE TABLE IF NOT EXISTS dns_records (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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
  dnssec_status    TEXT,
  resolver         TEXT,
  fingerprint      TEXT NOT NULL,
  attributes_json  TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_records_host ON dns_records (hostname, record_type, is_current);
CREATE INDEX IF NOT EXISTS idx_dns_records_asset ON dns_records (asset_id, is_current);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_unique ON dns_records (asset_id, fingerprint);


CREATE TABLE IF NOT EXISTS certificates (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE SET NULL,
  source           TEXT NOT NULL,
  source_id        TEXT,
  serial_number    TEXT,
  fingerprint_sha256 TEXT,
  issuer_cn        TEXT,
  issuer_org       TEXT,
  subject_cn       TEXT,
  not_before       TEXT,
  not_after        TEXT,
  dns_names        TEXT NOT NULL DEFAULT '[]',
  is_wildcard      INTEGER NOT NULL DEFAULT 0 CHECK (is_wildcard IN (0,1)),
  is_expired       INTEGER NOT NULL DEFAULT 0 CHECK (is_expired IN (0,1)),
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','expired','revoked','disappeared','unknown')),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  disappeared_at   TEXT,
  attributes_json  TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_target ON certificates (target_id, status);
CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON certificates (not_after, status);
CREATE INDEX IF NOT EXISTS idx_certificates_source ON certificates (source, source_id);

CREATE TABLE IF NOT EXISTS services (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  hostname         TEXT NOT NULL,
  ip_address       TEXT,
  port             INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
  transport        TEXT NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp','udp')),
  protocol         TEXT,
  service_name     TEXT,
  product          TEXT,
  version          TEXT,
  banner_redacted  TEXT,
  tls_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (tls_enabled IN (0,1)),
  tls_json         TEXT NOT NULL DEFAULT '{}',
  state            TEXT NOT NULL DEFAULT 'closed'
                   CHECK (state IN ('open','closed','filtered','open|filtered','unknown')),
  discovery_method TEXT NOT NULL,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  is_current       INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0,1)),
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_asset ON services (asset_id, is_current);
CREATE UNIQUE INDEX IF NOT EXISTS idx_services_unique ON services (asset_id, port, transport);

CREATE TABLE IF NOT EXISTS technologies (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  category         TEXT NOT NULL,
  version          TEXT,
  cpe              TEXT,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  detection_method TEXT NOT NULL,
  evidence_hash    TEXT,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  first_seen_version TEXT,
  previous_version TEXT,
  is_current       INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0,1)),
  removed_at       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_technologies_asset ON technologies (asset_id, is_current);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies (organization_id, name, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_technologies_unique ON technologies (asset_id, name, category);
