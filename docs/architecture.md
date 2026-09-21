# Watchtower — Architecture

## High-level design

Watchtower is structured as a single Cloudflare Worker with multiple entry
points (fetch, scheduled, queue) backed by Cloudflare bindings (D1, R2,
KV, Queues, Durable Objects).

```
                          ┌──────────────────┐
                          │  Telegram API    │
                          └────────┬─────────┘
                                   │ HTTPS webhook
                                   ▼
        ┌───────────────────────────────────────────────────┐
        │              Cloudflare Worker                    │
        │                                                  │
        │  fetch ──┬─ /telegram → handleTelegramWebhook    │
        │          ├─ /v1/*      → REST API                 │
        │          └─ /health    → status probe             │
        │                                                  │
        │  scheduled ─► handleScheduled (cron tick)        │
        │                                                  │
        │  queue ────┬─ SCAN_QUEUE   → handleScanMessage   │
        │            └─ NOTIFY_QUEUE → handleNotification   │
        │                                                  │
        │  DO classes: EmergencyStopDO, LockDO,             │
        │              RateLimiterDO                       │
        │                                                  │
        │  Bindings: D1, R2, KV, Queues                    │
        └──────────────────────────────────────────────────┘
                          │
                          ▼
        ┌──────────────────────────────────────────────────┐
        │  External scanner runners (HMAC-signed jobs)      │
        │  Container | Cloud Run | Fly.io | Lambda | GH-A   │
        │  nmap, subfinder, amass, httpx, nuclei, zap, burp │
        └──────────────────────────────────────────────────┘
```

## Request lifecycle: Telegram scan command

```
User: /scan_passive TGT_xxx
   │
   ▼
[Telegram webhook] ──► verifyWebhookSignature
   │                    ✓ secret matches TELEGRAM_WEBHOOK_SECRET
   ▼
[Telegram commands router] ──► parse "/scan_passive" + arg
   │
   ▼
[Check AUTHORIZED_TELEGRAM_IDS allowlist]
   │
   ▼
[Audit-log the command] ──► D1.audit_logs INSERT
   │
   ▼
[Check emergency stop] ──► EmergencyStopDO.fetch("check","target",id)
   │                       (fail-closed if blocked)
   ▼
[Insert scan row] ──► D1.scans INSERT status='queued'
   │
   ▼
[Enqueue job] ──► SCAN_QUEUE.send({...})
   │
   ▼
[Ack Telegram] ◄── 200 OK (within 1s of receiving the update)

[SCAN_QUEUE consumer (async)]
   │
   ▼
[Load target + scope] ──► D1.targets + D1.scope_entries
   │
   ▼
[Compile scope] ──► CompiledScope (regex/cidr/url rules)
   │
   ▼
[Acquire per-target lock] ──► LockDO.acquire(ttl=5min)
   │
   ▼
[Update scan status='running']
   │
   ▼
[Run providers in bounded concurrency (max 5)]
   │  ├─ CrtShProvider.discover()
   │  ├─ CertSpotterProvider.discover()
   │  ├─ CrtndstryProvider.discover()
   │  └─ DohProvider.discover()
   │
   ▼
[For each discovered asset:]
   │  ├─ Validate host against scope
   │  ├─ upsertAsset(...) → D1.assets INSERT/UPDATE
   │  └─ If certificate: upsertCertificate(...)
   │
   ▼
[For each in-scope subdomain:]
   │  ├─ HttpxProvider.probeUrl()
   │  │   └─ safeFetch() (SSRF-guarded)
   │  ├─ upsertAsset(url)
   │  └─ analyzeJsForAsset()
   │      ├─ extract <script src> from HTML
   │      ├─ For each JS URL:
   │      │   ├─ safeFetch (bounded to 2 MiB)
   │      │   ├─ sha256 hash
   │      │   ├─ upsertJavascriptFile (diff against previous)
   │      │   ├─ extractEndpoints (regex)
   │      │   └─ redactWithFingerprints (secrets → fingerprint only)
   │
   ▼
[Update scan status='completed'] ──► D1 UPDATE
   │
   ▼
[Audit-log completion]
   │
   ▼
[Release lock] ──► LockDO.release()
```

## Provider adapter pattern

Every recon source implements the same `ReconProvider` interface:

```ts
interface ReconProvider {
  readonly name: string;
  readonly kind: "certificate_transparency" | "dns" | "subdomain" | "http" | "scanner" | "cve" | "cloud";
  discover(input: { host: string }, ctx: ProviderContext): Promise<ProviderResult>;
}
```

Providers are composed in `buildRegistry()` and invoked in bounded
concurrency (max 5 simultaneous providers) by `runProviders()`. Provider
failures are recorded but never treated as asset removals — only successful
responses update the asset baseline.

## Memory safety

Cloudflare Workers have a 128 MB memory limit. Watchtower enforces:

- Per-response byte ceiling (`MAX_RESPONSE_BYTES` = 5 MiB)
- Per-CT-provider ceiling (`MAX_CERT_PROVIDER_RESPONSE_BYTES` = 25 MiB)
- Per-JS-file ceiling (`MAX_JS_FILE_BYTES` = 2 MiB)
- Bounded deduplication Sets (max 50,000 entries)
- Streaming reads via `ReadableStream` readers

Every `safeFetch()` call uses a streaming reader and aborts as soon as the
ceiling is reached. The first `maxBytes` bytes are retained; the rest are
discarded.

## Emergency stop semantics

The `EmergencyStopDO` Durable Object holds:

- `global` flag (kills all scans)
- `perOrganization` map
- `perTarget` map
- `perJob` map (cancellations)

Every cron tick and every queue consumer checks the DO state before
starting work. If blocked, the work is acked (skipped), NOT retried —
fail-closed behavior.

Auto-expiry: each activation has an optional TTL. On the next `check`,
expired activations are cleared automatically.

## External scanner runner protocol

1. **Job signing** — Worker signs a `RunnerJobPayload` with HMAC-SHA256
   using `API_HMAC_KEY`. The payload includes a 30-minute expiry.

2. **Runner fetches** the next pending job (polling `/v1/runner/pending`).

3. **Runner verifies** the HMAC signature. Reject if invalid or expired.

4. **Runner executes** the tool with the allowlisted arguments only.
   `validateToolArgs()` rejects any flag not in the tool's allowlist and
   any value containing shell metacharacters (`; | & $ \` > < \n \r`).

5. **Runner posts** the HMAC-signed result back to `/v1/runner/callback`.

6. **Worker verifies** the signature, checks `scope_validation_passed`,
   and persists the (redacted) output as evidence in R2.

Compromised runners cannot forge results without `API_HMAC_KEY` (held as a
Cloudflare secret). Compromised runners cannot exfiltrate other tenants'
data because every job is target-scoped and every API call is org-scoped.

## Multi-tenant isolation

Every DB query is parameterized by `organization_id`. The `users` table
couples Telegram identity to organization membership via the
`memberships` table. RBAC roles (`owner`, `administrator`, `analyst`,
`viewer`, `external_reviewer`) gate API endpoints in `api/router.ts` and
Telegram commands in `telegram/commands.ts`.
