-- ===========================================================================
-- Watchtower migration 0008 - seed roles and default retention policies
-- Idempotent: safe to re-run.
-- ===========================================================================

INSERT OR REPLACE INTO roles (id, name, description, rank, capabilities, created_at) VALUES
  ('role_owner', 'owner', 'Full control including membership, deletion and emergency stop.', 100,
   '["org:read","org:update","org:delete","org:emergency_stop","member:invite","member:remove","member:update_role","target:read","target:create","target:update","target:delete","scope:read","scope:create","scope:update","scope:delete","scope:pause","scan:read","scan:trigger_passive","scan:trigger_active","scan:trigger_intrusive","scan:cancel","finding:read","finding:update","finding:verify","finding:assign","finding:close","finding:report","evidence:read","evidence:download","report:create","report:share","integration:manage","runner:manage","wordlist:manage","audit:read","settings:update","approval:decide"]',
   strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('role_administrator', 'administrator', 'Manage targets, scope, scans, integrations and members. Cannot delete the organization.', 80,
   '["org:read","org:update","member:invite","member:remove","member:update_role","target:read","target:create","target:update","target:delete","scope:read","scope:create","scope:update","scope:delete","scope:pause","scan:read","scan:trigger_passive","scan:trigger_active","scan:cancel","finding:read","finding:update","finding:verify","finding:assign","finding:close","finding:report","evidence:read","evidence:download","report:create","integration:manage","runner:manage","wordlist:manage","audit:read","settings:update","approval:decide"]',
   strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('role_analyst', 'analyst', 'Triage findings, trigger passive monitoring, generate reports.', 60,
   '["org:read","target:read","scope:read","scan:read","scan:trigger_passive","finding:read","finding:update","finding:verify","finding:assign","finding:report","evidence:read","report:create","audit:read"]',
   strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('role_viewer', 'viewer', 'Read-only access to assets, findings and reports. No evidence download.', 40,
   '["org:read","target:read","scope:read","scan:read","finding:read","audit:read"]',
   strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('role_external_reviewer', 'external_reviewer', 'Client-side reviewer. Only sees explicitly shared findings and reports.', 20,
   '["org:read","target:read","finding:read","report:create"]',
   strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO retention_policies (id, organization_id, data_class, retention_days, legal_hold, purge_strategy, created_at, updated_at) VALUES
  ('ret_default_evidence',    NULL, 'evidence',      365, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_js',          NULL, 'js_snapshot',   180, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_report',      NULL, 'report',        730, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_audit',       NULL, 'audit',         730, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_finding',     NULL, 'finding',      1095, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_scan_result', NULL, 'scan_result',   365, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_notify',      NULL, 'notification',   90, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('ret_default_wordlist',    NULL, 'wordlist',      365, 0, 'delete',    strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));
