-- ===========================================================================
-- EXAMPLE authorized test configuration (LOCAL / STAGING ONLY)
--
-- Provided as the "example authorized test configuration" deliverable. It
-- seeds an organization, a confirmed authorization record and an intentionally
-- narrow scope so the full lifecycle can be exercised without touching
-- third-party infrastructure.
--
-- Scopes below point at example.com, which is reserved by RFC 2606 for
-- documentation and testing.
--
-- DO NOT apply to production. DO NOT widen these rules.
--
-- Apply with:  npm run db:seed:local
-- ===========================================================================

INSERT OR IGNORE INTO organizations (id, name, slug, program_type, program_url, emergency_stop, passive_only, settings_json, created_at, updated_at)
VALUES ('org_example', 'Watchtower Example Program', 'example-program', 'internal_pentest',
        'https://example.com/security-policy', 0, 1, '{"example":true}',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO users (id, telegram_user_id, telegram_username, email, display_name, telegram_verified_at, is_active, created_at, updated_at)
VALUES ('user_example_owner', '1000000001', 'example_owner', 'owner@example.com', 'Example Owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('user_example_analyst', '1000000002', 'example_analyst', 'analyst@example.com', 'Example Analyst',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO memberships (id, organization_id, user_id, role_id, status, invited_by, invited_at, accepted_at, mfa_required, allowed_chat_ids, created_at, updated_at)
VALUES ('mem_example_owner', 'org_example', 'user_example_owner', 'role_owner', 'active', 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1, '[]',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('mem_example_analyst', 'org_example', 'user_example_analyst', 'role_analyst', 'active', 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 0, '[]',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- ---------------------------------------------------------------------------
-- Authorized target: explicit ownership confirmation, 90 day window,
-- passive-only, active checks and intrusive testing disabled.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO targets (
  id, organization_id, name, description, criticality, data_sensitivity, internet_exposed, status,
  authorization_status, authorization_type, authorized_by_name, authorized_by_email, authorization_ref,
  authorization_note, valid_from, valid_until, passive_only, low_impact_active, intrusive_enabled,
  human_approval_required, max_requests_per_minute, max_concurrent_jobs, scan_profile,
  created_by, created_at, updated_at
) VALUES (
  'tgt_example', 'org_example', 'example.com (documentation target)',
  'Reserved documentation domain used to exercise the authorization lifecycle.',
  'low', 'public', 1, 'active',
  'confirmed', 'written_permission', 'Example Security Lead', 'security@example.com',
  'AUTH-EXAMPLE-0001',
  'Written permission on file for example.com only. Passive reconnaissance only.',
  strftime('%Y-%m-%dT00:00:00Z','now'), strftime('%Y-%m-%dT00:00:00Z','now','+90 days'),
  1, 0, 0, 1, 30, 1, 'passive-only',
  'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')
);

-- ---------------------------------------------------------------------------
-- Program rules
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO program_rules (id, organization_id, target_id, title, body, rule_type,
  enforce_no_dos, enforce_no_automated_scanning, enforce_no_credential_attacks, enforce_no_social_engineering,
  max_requests_per_minute, allowed_hours_utc, require_manual_approval, created_by, created_at, updated_at)
VALUES ('pr_example_1', 'org_example', 'tgt_example',
        'No denial-of-service testing',
        'Do not perform any testing that could degrade availability. No load generation, no stress testing, no resource-exhaustion payloads. Stop immediately if the target returns repeated 5xx responses.',
        'prohibited_action', 1, 0, 1, 1, 30, NULL, 1, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('pr_example_2', 'org_example', 'tgt_example',
        'No credential attacks',
        'Brute force, credential stuffing, password spraying, session guessing and authentication bypass testing are prohibited for this program.',
        'prohibited_action', 1, 0, 1, 1, 30, NULL, 1, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('pr_example_3', 'org_example', 'tgt_example',
        'No social engineering',
        'Phishing, pretexting, physical intrusion and any interaction with staff or customers are out of scope.',
        'prohibited_action', 1, 0, 1, 1, 30, NULL, 1, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('pr_example_4', 'org_example', 'tgt_example',
        'Automated scanning requires written approval',
        'Only the schedules explicitly enabled by the program owner may run automatically. Any other automated scan must be approved per action.',
        'testing_restriction', 1, 1, 1, 1, 30, NULL, 1, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('pr_example_5', 'org_example', 'tgt_example',
        'Findings must be reported privately first',
        'Do not disclose findings to third parties before the program owner has reviewed them. No automatic submission to any external platform.',
        'reporting_requirement', 1, 0, 1, 1, 30, NULL, 1, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- ---------------------------------------------------------------------------
-- Scope: root domain + two explicitly enumerated assets + one denied
-- wildcard. Everything not listed here is out of scope.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO scopes (id, organization_id, target_id, scope_type, value, display_value, status,
  is_primary, is_denylist, include_subdomains, notes,
  valid_from, valid_until, created_by, created_at, updated_at)
VALUES ('scp_example_root', 'org_example', 'tgt_example', 'domain', 'example.com',
        'example.com (root)', 'active', 1, 0, 1,
        'Primary authorized root domain. Wildcards are intentionally NOT used.',
        strftime('%Y-%m-%dT00:00:00Z','now'), strftime('%Y-%m-%dT00:00:00Z','now','+90 days'),
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('scp_example_www', 'org_example', 'tgt_example', 'domain', 'www.example.com',
        'www.example.com', 'active', 0, 0, 0,
        'Explicitly enumerated subdomain. Enumerating beats wildcards.',
        strftime('%Y-%m-%dT00:00:00Z','now'), strftime('%Y-%m-%dT00:00:00Z','now','+90 days'),
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('scp_example_api', 'org_example', 'tgt_example', 'api', 'https://api.example.com/v1',
        'api.example.com v1', 'active', 0, 0, 0,
        'Version-scoped API base URL. Later versions are NOT authorized.',
        strftime('%Y-%m-%dT00:00:00Z','now'), strftime('%Y-%m-%dT00:00:00Z','now','+90 days'),
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('scp_example_deny_wildcard', 'org_example', 'tgt_example', 'wildcard_domain', '*.internal.example.com',
        '*.internal.example.com (denied)', 'active', 0, 1, 1,
        'Demonstrates that an over-broad wildcard can be explicitly denied. Deny always beats allow.',
        strftime('%Y-%m-%dT00:00:00Z','now'), strftime('%Y-%m-%dT00:00:00Z','now','+90 days'),
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));


-- ---------------------------------------------------------------------------
-- Scope rules: ports, paths and HTTP methods
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO scope_rules (id, organization_id, scope_id, rule_kind, effect, value, value_end, notes, created_by, created_at)
VALUES ('rule_example_allow_443', 'org_example', 'scp_example_root', 'port', 'allow', '443', NULL,
        'HTTPS only for this program.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_allow_80', 'org_example', 'scp_example_root', 'port', 'allow', '80', NULL,
        'HTTP allowed for redirect observation only.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_22', 'org_example', 'scp_example_root', 'port', 'deny', '22', NULL,
        'SSH excluded: out of scope for this program.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_3389', 'org_example', 'scp_example_root', 'port', 'deny', '3389', NULL,
        'RDP excluded.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_admin', 'org_example', 'scp_example_root', 'path', 'deny', '/admin', NULL,
        'Administrative paths excluded from automated testing by program rules.',
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_logout', 'org_example', 'scp_example_root', 'path', 'deny', '/logout', NULL,
        'State-changing path excluded.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_delete', 'org_example', 'scp_example_root', 'method', 'deny', 'DELETE', NULL,
        'Destructive HTTP methods denied.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_put', 'org_example', 'scp_example_root', 'method', 'deny', 'PUT', NULL,
        'State-changing HTTP methods denied.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_patch', 'org_example', 'scp_example_root', 'method', 'deny', 'PATCH', NULL,
        'State-changing HTTP methods denied.', 'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
       ('rule_example_deny_post', 'org_example', 'scp_example_root', 'method', 'deny', 'POST', NULL,
        'POST requires per-action human approval; denied by default.',
        'user_example_owner', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- ---------------------------------------------------------------------------
-- Disabled-by-default schedule. Enabling it is an explicit operator action.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO schedules (id, organization_id, target_id, name, profile, mode, frequency,
  jitter_seconds, timezone, enabled, next_run_at, requires_approval, created_by, created_at, updated_at)
VALUES ('sch_example_passive', 'org_example', 'tgt_example', 'Passive hourly monitoring', 'passive-only',
        'passive', 'hourly', 600, 'UTC', 0, NULL, 0, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO retention_policies (id, organization_id, data_class, retention_days, legal_hold, purge_strategy, created_at, updated_at)
VALUES ('ret_example_evidence', 'org_example', 'evidence', 90, 0, 'delete',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- ---------------------------------------------------------------------------
-- Wordlist: tiny, project-authored, DISABLED. The module itself is off by
-- default (WORDLIST_MODULE_ENABLED=false) and this row is enabled = 0.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO wordlists (id, organization_id, name, version, category, source, description,
  r2_key, entry_count, max_word_length, content_hash, license_note, requires_authorization, is_builtin, enabled, created_by, created_at, updated_at)
VALUES ('wl_example_dirs', 'org_example', 'example-common-directories', '1.0.0', 'directories', 'builtin-safe-minimal',
        'Deliberately tiny builtin list used by tests. Never large, never aggressive.',
        'wordlists/builtin/example-common-directories.txt', 12, 256, 'recomputed-on-upload',
        'Project-authored. Safe to redistribute.', 1, 1, 0, 'user_example_owner',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

