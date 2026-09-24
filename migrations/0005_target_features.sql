-- ===========================================================================
-- Watchtower migration 0005 - per-target monitoring feature toggles
--
-- One row per (target, feature) that the operator changed. Missing rows mean
-- "default" (see src/db/queries/features.ts), so fresh targets need no
-- seeding and new feature keys stay backward compatible.
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS target_features (
  target_id   TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  feature_key TEXT NOT NULL
              CHECK (feature_key IN (
                'subdomain_enum', 'dns_brute', 'js_changes', 'fuzz_files',
                'deep_fuzz', 'status_watch', 'port_watch', 'nuclei'
              )),
  enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  updated_by  TEXT,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (target_id, feature_key)
);

CREATE INDEX IF NOT EXISTS idx_target_features_target ON target_features (target_id);
