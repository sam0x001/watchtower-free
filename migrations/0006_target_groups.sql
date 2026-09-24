-- ===========================================================================
-- Watchtower migration 0006 - target groups (categories)
--
-- A group is a named bucket of domains scanned under one id, e.g.
-- /target-add shop → shop.example.com + api.example.com report as "shop".
-- targets.group_id is nullable so pre-existing targets simply have no group.
-- Deleting a group detaches its members (they keep monitoring); use /remove
-- to delete domains.
-- ===========================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS target_groups (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  organization_id TEXT NOT NULL DEFAULT 'default',
  created_by      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- Category names are case-insensitive (matches the NOCASE lookup in
-- getTargetGroupByNameOrId): `/target-add shop` and `/target-add SHOP`
-- are the same category, not two.
CREATE UNIQUE INDEX IF NOT EXISTS idx_target_groups_name
  ON target_groups (name COLLATE NOCASE);

ALTER TABLE targets ADD COLUMN group_id TEXT REFERENCES target_groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_targets_group ON targets (group_id);
