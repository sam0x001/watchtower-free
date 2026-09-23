// src/db/queries/assets.ts
// Upsert helpers for assets + DNS records + certificates + JS files + services + tech.
//
// Every upsert returns `{ id, created }` (and `previous_sha` for JS files) so
// the scan consumer can detect "this is new" vs "this changed" and enqueue
// the appropriate notification.

import { randomId } from "../../crypto/hash.js";

export interface UpsertResult {
  id: string;
  /** true if a new row was inserted; false if an existing row was updated. */
  created: boolean;
  /** For JS files: the previous SHA-256 hash when the file changed. */
  previous_sha?: string;
}

/**
 * Asset-family tables (`assets`, `dns_records`, `certificates`, `services`,
 * `technologies`, `api_endpoints`, `javascript_files`) are keyed off the
 * organization + target in the canonical schema and require both on INSERT.
 * Callers resolve these once per scan and pass them alongside the asset id.
 */
export type AssetCtxInput = { organizationId: string; targetId: string; assetId: string } | string;

async function resolveCtx(db: D1Database, ctx: AssetCtxInput): Promise<{ organizationId: string; targetId: string; assetId: string }> {
  if (typeof ctx !== "string") return ctx;
  const row = await db
    .prepare(`SELECT organization_id, target_id FROM assets WHERE id = ?`)
    .bind(ctx)
    .first<{ organization_id: string; target_id: string }>();
  return { organizationId: row?.organization_id ?? "", targetId: row?.target_id ?? "", assetId: ctx };
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function mapScopeState(scopeStatus: string): string {
  if (scopeStatus === "in_scope") return "allowed";
  if (scopeStatus === "out_of_scope") return "denied";
  return "unknown";
}

export async function upsertAsset(
  db: D1Database,
  targetId: string,
  type: string,
  value: string,
  normalized: string,
  scopeStatus: string,
  metadata: Record<string, unknown> = {},
): Promise<UpsertResult> {
  const now = new Date().toISOString();
  const existing = await db
    .prepare(`SELECT id FROM assets WHERE target_id = ? AND asset_type = ? AND identifier = ?`)
    .bind(targetId, type, normalized)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE assets SET last_seen = ?, scope_state = ?, in_scope = ?, attributes_json = ? WHERE id = ?`)
      .bind(now, mapScopeState(scopeStatus), scopeStatus === "in_scope" ? 1 : 0, JSON.stringify(metadata), existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("asset", 16);
  const orgRow = await db
    .prepare(`SELECT organization_id FROM targets WHERE id = ?`)
    .bind(targetId)
    .first<{ organization_id: string }>();
  const organizationId = orgRow?.organization_id ?? "";
  await db
    .prepare(`INSERT INTO assets (id, organization_id, target_id, asset_type, identifier, display_name, in_scope, scope_state, source, first_seen, last_seen, attributes_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scan', ?, ?, ?, ?, ?)`)
    .bind(id, organizationId, targetId, type, normalized, value, scopeStatus === "in_scope" ? 1 : 0, mapScopeState(scopeStatus), now, now, JSON.stringify(metadata), now, now)
    .run();
  return { id, created: true };
}

export async function markAssetRemoved(db: D1Database, assetId: string): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE assets SET status = 'removed', removed_at = ?, removed_reason = 'scan' WHERE id = ?`)
    .bind(now, assetId)
    .run();
  await db
    .prepare(`UPDATE dns_records SET removed_at = ?, is_current = 0 WHERE asset_id = ? AND removed_at IS NULL`)
    .bind(now, assetId)
    .run();
  await db
    .prepare(`UPDATE certificates SET status = 'disappeared', disappeared_at = ? WHERE asset_id = ? AND disappeared_at IS NULL`)
    .bind(now, assetId)
    .run();
}

export async function upsertDnsRecord(
  db: D1Database,
  ctx: AssetCtxInput,
  type: string,
  name: string,
  value: string,
  ttl: number | null,
): Promise<UpsertResult> {
  const c = await resolveCtx(db, ctx);
  const now = new Date().toISOString();
  // Re-resurrect if previously removed
  await db
    .prepare(`UPDATE dns_records SET removed_at = NULL, is_current = 1, last_seen = ?, value = ? WHERE asset_id = ? AND record_type = ? AND hostname = ? AND value = ?`)
    .bind(now, value, c.assetId, type, name, value)
    .run();
  const existing = await db
    .prepare(`SELECT id FROM dns_records WHERE asset_id = ? AND record_type = ? AND hostname = ? AND value = ? AND removed_at IS NULL`)
    .bind(c.assetId, type, name, value)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE dns_records SET last_seen = ? WHERE id = ?`)
      .bind(now, existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("dns", 12);
  const fingerprint = Buffer.from(`${type}|${name}|${value}`).toString("base64url");
  await db
    .prepare(`INSERT INTO dns_records (id, organization_id, target_id, asset_id, hostname, record_type, value, ttl, first_seen, last_seen, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, c.organizationId, c.targetId, c.assetId, name, type, value, ttl, now, now, fingerprint)
    .run();
  return { id, created: true };
}

export async function upsertCertificate(
  db: D1Database,
  ctx: AssetCtxInput,
  issuer: string,
  serial: string,
  notBefore: string | null,
  notAfter: string | null,
  sans: string[],
): Promise<UpsertResult> {
  const c = await resolveCtx(db, ctx);
  const now = new Date().toISOString();
  const existing = await db
    .prepare(`SELECT id FROM certificates WHERE asset_id = ? AND serial_number = ?`)
    .bind(c.assetId, serial)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE certificates SET last_seen = ?, not_after = ?, status = 'active', disappeared_at = NULL WHERE id = ?`)
      .bind(now, notAfter, existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("cert", 12);
  await db
    .prepare(`INSERT INTO certificates (id, organization_id, target_id, asset_id, source, serial_number, issuer_cn, not_before, not_after, dns_names, first_seen, last_seen) VALUES (?, ?, ?, ?, 'scan', ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, c.organizationId, c.targetId, c.assetId, serial, issuer, notBefore, notAfter, JSON.stringify(sans), now, now)
    .run();
  return { id, created: true };
}

export async function upsertJavascriptFile(
  db: D1Database,
  ctx: AssetCtxInput,
  url: string,
  sha256: string,
  sizeBytes: number,
  etag: string | null,
  lastModified: string | null,
  contentType: string | null,
): Promise<UpsertResult> {
  const c = await resolveCtx(db, ctx);
  const now = new Date().toISOString();
  const existing = await db
    .prepare(`SELECT id, content_hash FROM javascript_files WHERE asset_id = ? AND url_canonical = ? AND status = 'active'`)
    .bind(c.assetId, url)
    .first<{ id: string; content_hash: string | null }>();
  if (existing) {
    if ((existing.content_hash ?? null) !== sha256) {
      await db
        .prepare(`UPDATE javascript_files SET content_hash = ?, content_length = ?, etag = ?, last_modified = ?, content_type = ?, last_seen = ? WHERE id = ?`)
        .bind(sha256, sizeBytes, etag, lastModified, contentType, now, existing.id)
        .run();
      return { id: existing.id, created: false, previous_sha: existing.content_hash ?? undefined };
    }
    await db
      .prepare(`UPDATE javascript_files SET last_seen = ? WHERE id = ?`)
      .bind(now, existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("js", 16);
  await db
    .prepare(`INSERT INTO javascript_files (id, organization_id, target_id, asset_id, url, url_canonical, hostname, content_hash, content_length, etag, last_modified, content_type, discovered_via, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scan', ?, ?)`)
    .bind(id, c.organizationId, c.targetId, c.assetId, url, url, hostnameOf(url), sha256, sizeBytes, etag, lastModified, contentType, now, now)
    .run();
  return { id, created: true };
}

export async function insertApiEndpoint(
  db: D1Database,
  ctx: AssetCtxInput,
  method: string,
  path: string,
  parameters: Record<string, unknown>[],
  source: string,
): Promise<{ id: string; inserted: boolean }> {
  const c = await resolveCtx(db, ctx);
  const now = new Date().toISOString();
  const existing = await db
    .prepare(`SELECT id FROM api_endpoints WHERE asset_id = ? AND method = ? AND path = ? AND status = 'active'`)
    .bind(c.assetId, method, path)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE api_endpoints SET last_seen = ? WHERE id = ?`)
      .bind(now, existing.id)
      .run();
    return { id: existing.id, inserted: false };
  }
  const id = randomId("api", 12);
  await db
    .prepare(`INSERT INTO api_endpoints (id, organization_id, target_id, asset_id, base_url, method, path, parameters, discovery_source, first_seen, last_seen) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`)
    .bind(id, c.organizationId, c.targetId, c.assetId, method, path, JSON.stringify(parameters), source, now, now)
    .run();
  return { id, inserted: true };
}

// ---------------------------------------------------------------------------
// HTTP service + technology upserts
// ---------------------------------------------------------------------------

export interface ServiceUpsertResult {
  id: string;
  created: boolean;
  /** Fields that changed if the service already existed. */
  changes: { field: string; before: string; after: string }[];
}

/**
 * Upserts a row in `services` for an HTTP/HTTPS endpoint. Returns the list of
 * fields that changed since the previous probe — used to drive "title changed",
 * "server header changed", "status changed" alerts.
 */
export async function upsertService(
  db: D1Database,
  assetId: string,
  port: number,
  protocol: string,
  banner: string | null,
  tlsJson: string | null,
  httpStatus: number | null,
  httpTitle: string | null,
  serverHeader: string | null,
): Promise<ServiceUpsertResult> {
  const existing = await db
    .prepare(`SELECT id, tls_json, banner_redacted, service_name FROM services WHERE asset_id = ? AND port = ? AND removed_at IS NULL`)
    .bind(assetId, port, protocol)
    .first<{ id: string; tls_json: string; banner_redacted: string | null; service_name: string | null }>();

  const changes: { field: string; before: string; after: string }[] = [];

  if (existing) {
    if (Number((JSON.parse(existing.tls_json || '{}') as Record<string, unknown>).status ?? null) !== httpStatus) {
      changes.push({ field: "http_status", before: String((JSON.parse(existing.tls_json || "{}") as Record<string, unknown>).status ?? "—"), after: String(httpStatus ?? "—") });
    }
    if (((JSON.parse(existing.tls_json || '{}') as Record<string, unknown>).title ?? null) !== (httpTitle ?? null)) {
      changes.push({ field: "http_title", before: String((JSON.parse(existing.tls_json || "{}") as Record<string, unknown>).title ?? "—"), after: httpTitle ?? "—" });
    }
    if ((existing.service_name ?? null) !== (serverHeader ?? null)) {
      changes.push({ field: "server_header", before: existing.service_name ?? "—", after: serverHeader ?? "—" });
    }
    if ((existing.banner_redacted ?? null) !== (banner ?? null)) {
      changes.push({ field: "banner", before: existing.banner_redacted ?? "—", after: banner ?? "—" });
    }
    if (changes.length > 0) {
      await db
        .prepare(`UPDATE services SET tls_json = ?, banner_redacted = ?, service_name = ?, last_seen = ?, updated_at = ? WHERE id = ?`)
        .bind(JSON.stringify({ status: httpStatus, title: httpTitle, server: serverHeader, extra: tlsJson }), banner, serverHeader, new Date().toISOString(), new Date().toISOString(), existing.id)
        .run();
    } else {
      await db
        .prepare(`UPDATE services SET last_seen = ? WHERE id = ?`)
        .bind(new Date().toISOString(), existing.id)
        .run();
    }
    return { id: existing.id, created: false, changes };
  }

  const id = randomId("svc", 12);
  await db
    .prepare(`INSERT INTO services (id, organization_id, target_id, asset_id, hostname, port, transport, protocol, service_name, banner_redacted, tls_json, state, discovery_method, confidence, first_seen, last_seen, created_at, updated_at) VALUES (?, (SELECT organization_id FROM assets WHERE id = ?), (SELECT target_id FROM assets WHERE id = ?), ?, (SELECT identifier FROM assets WHERE id = ?), ?, 'tcp', ?, ?, ?, ?, 'open', 'scan', 0.7, ?, ?, ?, ?)`)
    .bind(id, assetId, assetId, assetId, assetId, port, protocol, serverHeader, banner, JSON.stringify({ status: httpStatus, title: httpTitle, server: serverHeader, extra: tlsJson }), new Date().toISOString(), new Date().toISOString(), new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true, changes: [] };
}

export interface TechnologyUpsertResult {
  id: string;
  /** true if this technology wasn't previously recorded for the asset. */
  created: boolean;
  /** true if the version changed since the previous probe. */
  versionChanged: boolean;
  /** Previous version, if versionChanged. */
  previousVersion: string | null;
}

/**
 * Upserts a row in `technologies` for a detected tech on an asset. Detects
 * version upgrades ("nginx 1.23 → nginx 1.25") and surfaces those as alerts.
 */
export async function upsertTechnology(
  db: D1Database,
  assetId: string,
  name: string,
  version: string | null,
  confidence: number,
  source: string,
): Promise<TechnologyUpsertResult> {
  const existing = await db
    .prepare(`SELECT id, version FROM technologies WHERE asset_id = ? AND name = ? AND removed_at IS NULL`)
    .bind(assetId, name)
    .first<{ id: string; version: string | null }>();

  if (existing) {
    const versionChanged = (existing.version ?? null) !== (version ?? null);
    if (versionChanged) {
      await db
        .prepare(`UPDATE technologies SET version = ?, confidence = ?, detection_method = ?, last_seen = ?, updated_at = ? WHERE id = ?`)
        .bind(version, confidence, source, new Date().toISOString(), new Date().toISOString(), existing.id)
        .run();
    } else {
      await db
        .prepare(`UPDATE technologies SET last_seen = ? WHERE id = ?`)
        .bind(new Date().toISOString(), existing.id)
        .run();
    }
    return {
      id: existing.id,
      created: false,
      versionChanged,
      previousVersion: versionChanged ? existing.version : null,
    };
  }

  const id = randomId("tech", 12);
  await db
    .prepare(`INSERT INTO technologies (id, organization_id, target_id, asset_id, name, category, version, confidence, detection_method, first_seen, last_seen, created_at, updated_at) VALUES (?, (SELECT organization_id FROM assets WHERE id = ?), (SELECT target_id FROM assets WHERE id = ?), ?, ?, 'fingerprint', ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, assetId, assetId, name, version, confidence, source, new Date().toISOString(), new Date().toISOString(), new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true, versionChanged: false, previousVersion: null };
}
