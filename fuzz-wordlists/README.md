# Watchtower fuzz wordlists
#
# These wordlists are DISABLED BY DEFAULT. They are only loaded when an
# authorized operator explicitly enables wordlist monitoring for a target
# via /scan_active <target_id> confirm and adds a scan profile like
# `low-impact-web-content` or `low-impact-api-discovery`.
#
# Every entry is sanitized at load time:
#  - blank lines and comments (`#`) are ignored
#  - path traversal (`..`) is rejected
#  - NUL bytes and control characters are rejected
#  - shell metacharacters (`; | & $ \` > <`) are rejected
#  - entries longer than 256 chars are rejected
#  - duplicates are removed
#
# Per-target rate limits, per-host concurrency, delay, and jitter are
# enforced by the scan profile in src/modules/wordlist.ts.

## Files

- `directories.txt` — common directories
- `files.txt` — common files (config, env, manifests)
- `subdomains.txt` — common subdomain prefixes (DNS only)
- `api.txt` — common API routes

## Adding your own

Wordlists are stored in the `wordlists` D1 table. Load via the REST API or
via a SQL INSERT. See `src/modules/wordlist.ts:storeWordlist()` for the
schema.
