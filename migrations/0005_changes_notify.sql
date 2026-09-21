-- ===========================================================================
-- Watchtower migration 0005 - change detection, notifications, schedules,
-- integrations and external scanner runners
-- ===========================================================================
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- snapshots - per-asset baseline used by the diff engine
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_snapshots (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  scan_id          TEXT REFERENCES scans(id) ON DELETE SET NULL,
  snapshot_kind    TEXT NOT NULL,
  -- Normalized, volatile-field-stripped observation set.
  data_json        TEXT NOT NULL,
  data_hash        TEXT NOT NULL,
  item_count       INTEGER NOT NULL DEFAULT 0,
  is_baseline      INTEGER NOT NULL DEFAULT 0 CHECK (is_baseline IN (0,1)),
  captured_at      TEXT NOT NULL,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_asset ON asset_snapshots (asset_id, snapshot_kind, captured_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_hash ON asset_snapshots (asset_id, snapshot_kind, data_hash);

-- ---------------------------------------------------------------------------
-- changes - the diff engine output. Feeds findings and notifications.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS changes (
  id               TEXT PRIMARY KEY,
  change_ref       TEXT NOT NULL UNIQUE,   -- CHG-000123
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id         TEXT REFERENCES assets(id) ON DELETE SET NULL,
  scan_id          TEXT REFERENCES scans(id) ON DELETE SET NULL,
  job_id           TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  finding_id       TEXT REFERENCES findings(id) ON DELETE SET NULL,
  parent_change_id TEXT REFERENCES changes(id) ON DELETE SET NULL,
  change_type      TEXT NOT NULL
                   CHECK (change_type IN (
                     'new_subdomain','removed_subdomain','new_dns_record','removed_dns_record',
                     'new_ip','removed_ip','asn_change','certificate_issued','certificate_expiring',
                     'certificate_expired','certificate_replaced','new_port','closed_port','port_change',
                     'service_change','http_status_change','https_availability_change','redirect_change',
                     'title_change','content_change','content_hash_change','security_header_change',
                     'tls_change','technology_change','server_header_change','new_javascript',
                     'removed_javascript','javascript_change','javascript_endpoint_added',
                     'javascript_endpoint_removed','new_api_route','removed_api_route','api_version_change',
                     'openapi_change','robots_change','sitemap_change','new_file','removed_file',
                     'new_directory','new_source_map','new_backup_file','new_config_file','new_secret_candidate',
                     'new_cve','vulnerable_version_exposed','finding_resolved','service_outage',
                     'scope_violation','wordlist_new_endpoint','wordlist_removed_endpoint',
                     'wordlist_content_changed','directory_listing_exposed','cloud_storage_reference',
                     'auth_behavior_change')),
  category         TEXT NOT NULL
                   CHECK (category IN ('asset','dns','certificate','service','http','javascript','api','technology','vulnerability','secret','scope','availability','exposure')),
  title            TEXT NOT NULL,
  summary          TEXT NOT NULL,
  severity         TEXT NOT NULL DEFAULT 'informational'
                   CHECK (severity IN ('informational','low','medium','high','critical')),
  previous_severity TEXT,
  confidence       REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  severity_score   REAL,
  significance_score REAL,
  detection_source TEXT NOT NULL,
  scan_profile     TEXT NOT NULL,
  entity           TEXT NOT NULL,
  url              TEXT,
  hostname         TEXT,
  port             INTEGER,
  before_json      TEXT,
  after_json       TEXT,
  before_hash      TEXT,
  after_hash       TEXT,
  evidence_hash    TEXT,
  is_meaningful    INTEGER NOT NULL DEFAULT 1 CHECK (is_meaningful IN (0,1)),
  is_duplicate     INTEGER NOT NULL DEFAULT 0 CHECK (is_duplicate IN (0,1)),
  duplicate_of     TEXT REFERENCES changes(id),
  review_state     TEXT NOT NULL DEFAULT 'unreviewed'
                   CHECK (review_state IN ('unreviewed','expected','suppressed','confirmed','false_positive','needs_review')),
  suppressed_until TEXT,
  suppressed_by    TEXT,
  notified_at      TEXT,
  notification_count INTEGER NOT NULL DEFAULT 0,
  first_seen       TEXT NOT NULL,
  previous_seen_at TEXT,
  last_seen        TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changes_target ON changes (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_type ON changes (organization_id, change_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_severity ON changes (severity, notified_at);
CREATE INDEX IF NOT EXISTS idx_changes_asset ON changes (asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_dedupe ON changes (asset_id, change_type, after_hash);
CREATE INDEX IF NOT EXISTS idx_changes_finding ON changes (finding_id);


-- ---------------------------------------------------------------------------
-- notifications
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  integration_id   TEXT,
  change_id        TEXT REFERENCES changes(id) ON DELETE CASCADE,
  finding_id       TEXT REFERENCES findings(id) ON DELETE CASCADE,
  channel          TEXT NOT NULL
                   CHECK (channel IN ('telegram','slack','email','jira','github','webhook','digest')),
  destination      TEXT NOT NULL,
  alert_type       TEXT NOT NULL,
  severity         TEXT NOT NULL DEFAULT 'informational'
                   CHECK (severity IN ('informational','low','medium','high','critical')),
  title            TEXT NOT NULL,
  body_redacted    TEXT NOT NULL,
  dedupe_key       TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','sent','failed','suppressed','deduplicated','expired')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  max_attempts     INTEGER NOT NULL DEFAULT 5,
  next_attempt_at  TEXT,
  last_error       TEXT,
  provider_message_id TEXT,
  requires_permission INTEGER NOT NULL DEFAULT 0 CHECK (requires_permission IN (0,1)),
  permission_granted_at TEXT,
  sent_at          TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_notifications_dedupe ON notifications (dedupe_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_target ON notifications (target_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_preferences (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT REFERENCES targets(id) ON DELETE CASCADE,
  user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
  channel          TEXT NOT NULL CHECK (channel IN ('telegram','slack','email','jira','github','webhook','digest')),
  destination      TEXT,
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  min_severity     TEXT NOT NULL DEFAULT 'low'
                   CHECK (min_severity IN ('informational','low','medium','high','critical')),
  immediate_types  TEXT NOT NULL DEFAULT '[]',
  quiet_hours_utc  TEXT,
  digest_frequency TEXT NOT NULL DEFAULT 'daily'
                   CHECK (digest_frequency IN ('none','hourly','daily','weekly')),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notify_prefs_lookup ON notification_preferences (organization_id, target_id, user_id, channel);


CREATE TABLE IF NOT EXISTS schedules (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  profile          TEXT NOT NULL,
  mode             TEXT NOT NULL CHECK (mode IN ('passive','low_impact_active','intrusive')),
  frequency        TEXT NOT NULL
                   CHECK (frequency IN ('hourly','every_6_hours','every_12_hours','daily','weekly','custom')),
  cron_expression  TEXT,
  jitter_seconds   INTEGER NOT NULL DEFAULT 300,
  timezone         TEXT NOT NULL DEFAULT 'UTC',
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  next_run_at      TEXT,
  last_run_at      TEXT,
  last_scan_id     TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  max_failures     INTEGER NOT NULL DEFAULT 5,
  requires_approval INTEGER NOT NULL DEFAULT 0 CHECK (requires_approval IN (0,1)),
  created_by       TEXT NOT NULL REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules (enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_schedules_target ON schedules (target_id);

CREATE TABLE IF NOT EXISTS integrations (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL
                   CHECK (kind IN ('slack','jira','github','email','generic_webhook','pagerduty','teams','splunk')),
  name             TEXT NOT NULL,
  config_json      TEXT NOT NULL DEFAULT '{}',
  secret_ref       TEXT,
  webhook_secret_ref TEXT,
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  event_types      TEXT NOT NULL DEFAULT '[]',
  min_severity     TEXT NOT NULL DEFAULT 'low'
                   CHECK (min_severity IN ('informational','low','medium','high','critical')),
  created_by       TEXT NOT NULL REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations (organization_id, kind, enabled);
