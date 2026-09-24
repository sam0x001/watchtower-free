# Watchtower fuzz wordlists

These wordlists are bundled into the Worker as **text modules** (see the
`[[rules]]` block in `wrangler.toml` and the `.txt` plugin in
`vitest.config.ts`). There is no `wordlists` table and no REST API — edit a
file here and redeploy.

## Files

| File | Used by | Gate |
|---|---|---|
| `subdomains.txt` | DNS bruteforce (`src/modules/dns-bruteforce.ts`) | `dns_brute` feature |
| `api.txt` | common-file fuzzing (`src/modules/wordlist.ts`) | `fuzz_files` feature |
| `directories.txt` | common-file fuzzing | `fuzz_files` feature |
| `files.txt` | common-file fuzzing | `fuzz_files` feature |
| `fuzz.txt` | common-file fuzzing (largest list) | `fuzz_files` feature |

Features are toggled per **domain** with `/feature <domain> <key> on|off`.

## Sanitization (applied at load time)

- blank lines and `#` comments are skipped
- path traversal (`..`) is rejected
- NUL and other control characters are rejected
- entries longer than 256 characters are rejected
- anything outside `[A-Za-z0-9_\-/.~:@!$&'()*+,;=%]` is rejected
  (this covers spaces, backticks, `|`, `<`, `>`, quotes, …)
- trailing CR/LF is trimmed like any other line ending

## Pacing (free tier)

- **Bruteforce**: `BRUTEFORCE_CHUNK` entries per cron tick (default 300) with
  `BRUTEFORCE_CONCURRENCY` parallel DoH lookups (default 16); the cursor
  persists in KV (`bf:<targetId>`) and wraps to 0 after a full cycle.
  A wildcard-DNS guard filters hits that only resolve to wildcard IPs.
- **Fuzzing**: `FUZZ_REQUESTS_PER_TICK` requests per host per tick (default
  40), 2 concurrent, 250 ms delay, 8 s timeout, stops the host chunk on 429.
  The cursor persists in KV (`fuzz:<targetId>:<host>`); a host flagged
  `deep_fuzz` + newly discovered gets a doubled slice.

## Adding entries

Just append to the right `.txt` file (one entry per line) and deploy with
`npm run deploy`. Keep entries relative (`admin/`, `.env`, `api/v1/…`) —
they are joined onto each in-scope base URL, and scope-checked before use.
