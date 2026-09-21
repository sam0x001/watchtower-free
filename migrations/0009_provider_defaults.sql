-- ===========================================================================
-- Watchtower migration 0009 - builtin provider registry defaults
-- All intrusive / native-tool providers default to DISABLED (enabled = 0).
-- ===========================================================================

INSERT OR IGNORE INTO providers (id, organization_id, adapter, kind, enabled, requires_runner, requires_credentials, rate_limit_per_minute, max_response_bytes, timeout_ms, priority, config_json, health_state, created_at, updated_at) VALUES
  ('prov_crtsh',       NULL, 'crtsh',            'certificate_transparency', 1, 0, 0, 10, 5242880,  20000, 10, '{"includeExpired":true}',  '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_certspotter', NULL, 'certspotter',      'certificate_transparency', 1, 0, 0, 20, 5242880,  15000, 20, '{"includeSubdomains":true}','{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_crtndstry',   NULL, 'crtndstry',        'certificate_transparency', 0, 0, 0, 10, 2097152,  20000, 30, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_doh',         NULL, 'doh_resolver',     'dns',                      1, 0, 0, 60, 1048576,   8000, 10, '{"resolver":"https://cloudflare-dns.com/dns-query"}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_httpx',       NULL, 'httpx_remote',     'http',                     1, 1, 0, 30, 5242880,  15000, 10, '{"followRedirects":true,"maxRedirects":5}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_subfinder',   NULL, 'subfinder_remote', 'subdomain',                1, 1, 0, 10, 5242880,  60000, 10, '{"passiveOnly":true}',     '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_amass',       NULL, 'amass_remote',     'subdomain',                1, 1, 0,  5, 5242880, 120000, 20, '{"passiveOnly":true}',     '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_nmap',        NULL, 'nmap_remote',      'service',                  0, 1, 0,  2, 2097152, 300000, 10, '{"profile":"safe-service-discovery"}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_nuclei',      NULL, 'nuclei_remote',    'vulnerability',            0, 1, 0,  5, 5242880, 600000, 10, '{"severity":"info,low,medium,high,critical","excludeIntrusive":true}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_zap',         NULL, 'zap_remote',       'vulnerability',            0, 1, 0,  2, 5242880, 900000, 20, '{"scanPolicy":"safe-baseline","activeScan":false}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_burp',        NULL, 'burp_remote',      'vulnerability',            0, 1, 1,  2, 5242880, 900000, 30, '{"mode":"rest_api","scanType":"crawl_and_audit_readonly"}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_nvd',         NULL, 'nvd_cve',          'cve',                      1, 0, 0, 10, 2097152,  15000, 10, '{"apiVersion":"2.0"}',     '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_osv',         NULL, 'osv_cve',          'cve',                      1, 0, 0, 30, 2097152,  15000, 20, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_epss',        NULL, 'epss_provider',    'vulnerability',            1, 0, 0, 30, 2097152,  15000, 10, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_github',      NULL, 'github_adapter',   'repository',               0, 0, 1, 30, 2097152,  15000, 10, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_slack',       NULL, 'slack_adapter',    'notification',             0, 0, 1, 60,  262144,  10000, 10, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_jira',        NULL, 'jira_adapter',     'notification',             0, 0, 1, 30,  262144,  15000, 20, '{}',                       '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('prov_screenshot',  NULL, 'screenshot_remote','screenshot',               0, 1, 0,  5, 5242880,  60000, 10, '{"disableDownloads":true,"blockCloudMetadata":true}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));
