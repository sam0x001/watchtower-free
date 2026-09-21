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

export async function upsertAsset(
  db: D1Database,
  targetId: string,
  type: string,
  value: string,
  normalized: string,
  scopeStatus: string,
  metadata: Record<string, unknown> = {},
): Promise<UpsertResult> {
  const existing = await db
    .prepare(`SELECT id FROM assets WHERE target_id = ? AND type = ? AND normalized = ?`)
    .bind(targetId, type, normalized)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE assets SET last_seen = ?, scope_status = ?, metadata_json = ? WHERE id = ?`)
      .bind(new Date().toISOString(), scopeStatus, JSON.stringify(metadata), existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("asset", 16);
  await db
    .prepare(`INSERT INTO assets (id, target_id, type, value, normalized, first_seen, last_seen, scope_status, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, targetId, type, value, normalized, new Date().toISOString(), new Date().toISOString(), scopeStatus, JSON.stringify(metadata))
    .run();
  return { id, created: true };
}

export async function markAssetRemoved(db: D1Database, assetId: string): Promise<void> {
  await db
    .prepare(`UPDATE assets SET scope_status = 'out_of_scope' WHERE id = ?`)
    .bind(assetId)
    .run();
  await db
    .prepare(`UPDATE dns_records SET removed_at = ? WHERE asset_id = ? AND removed_at IS NULL`)
    .bind(new Date().toISOString(), assetId)
    .run();
  await db
    .prepare(`UPDATE certificates SET removed_at = ? WHERE asset_id = ? AND removed_at IS NULL`)
    .bind(new Date().toISOString(), assetId)
    .run();
}

export async function upsertDnsRecord(
  db: D1Database,
  assetId: string,
  type: string,
  name: string,
  value: string,
  ttl: number | null,
): Promise<UpsertResult> {
  // Re-resurrect if previously removed
  await db
    .prepare(`UPDATE dns_records SET removed_at = NULL, last_seen = ?, value = ? WHERE asset_id = ? AND type = ? AND name = ? AND value = ?`)
    .bind(new Date().toISOString(), value, assetId, type, name, value)
    .run();
  const existing = await db
    .prepare(`SELECT id FROM dns_records WHERE asset_id = ? AND type = ? AND name = ? AND value = ? AND removed_at IS NULL`)
    .bind(assetId, type, name, value)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE dns_records SET last_seen = ? WHERE id = ?`)
      .bind(new Date().toISOString(), existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("dns", 12);
  await db
    .prepare(`INSERT INTO dns_records (id, asset_id, type, name, value, ttl, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, type, name, value, ttl, new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true };
}

export async function upsertCertificate(
  db: D1Database,
  assetId: string,
  issuer: string,
  serial: string,
  notBefore: string | null,
  notAfter: string | null,
  sans: string[],
): Promise<UpsertResult> {
  const existing = await db
    .prepare(`SELECT id FROM certificates WHERE asset_id = ? AND serial = ?`)
    .bind(assetId, serial)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE certificates SET last_seen = ?, not_after = ?, removed_at = NULL WHERE id = ?`)
      .bind(new Date().toISOString(), notAfter, existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("cert", 12);
  await db
    .prepare(`INSERT INTO certificates (id, asset_id, issuer, serial, not_before, not_after, sans_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, issuer, serial, notBefore, notAfter, JSON.stringify(sans), new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true };
}

export async function upsertJavascriptFile(
  db: D1Database,
  assetId: string,
  url: string,
  sha256: string,
  sizeBytes: number,
  etag: string | null,
  lastModified: string | null,
  contentType: string | null,
): Promise<UpsertResult> {
  const existing = await db
    .prepare(`SELECT id, sha256 FROM javascript_files WHERE asset_id = ? AND url = ? AND removed_at IS NULL`)
    .bind(assetId, url)
    .first<{ id: string; sha256: string }>();
  if (existing) {
    if (existing.sha256 !== sha256) {
      await db
        .prepare(`UPDATE javascript_files SET sha256 = ?, size_bytes = ?, etag = ?, last_modified = ?, content_type = ?, last_seen = ? WHERE id = ?`)
        .bind(sha256, sizeBytes, etag, lastModified, contentType, new Date().toISOString(), existing.id)
        .run();
      return { id: existing.id, created: false, previous_sha: existing.sha256 };
    }
    await db
      .prepare(`UPDATE javascript_files SET last_seen = ? WHERE id = ?`)
      .bind(new Date().toISOString(), existing.id)
      .run();
    return { id: existing.id, created: false };
  }
  const id = randomId("js", 16);
  await db
    .prepare(`INSERT INTO javascript_files (id, asset_id, url, sha256, size_bytes, etag, last_modified, content_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, url, sha256, sizeBytes, etag, lastModified, contentType, new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true };
}

export async function insertApiEndpoint(
  db: D1Database,
  assetId: string,
  method: string,
  path: string,
  parameters: Record<string, unknown>[],
  source: string,
): Promise<{ id: string; inserted: boolean }> {
  const existing = await db
    .prepare(`SELECT id FROM api_endpoints WHERE asset_id = ? AND method = ? AND path = ? AND removed_at IS NULL`)
    .bind(assetId, method, path)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE api_endpoints SET last_seen = ? WHERE id = ?`)
      .bind(new Date().toISOString(), existing.id)
      .run();
    return { id: existing.id, inserted: false };
  }
  const id = randomId("api", 12);
  await db
    .prepare(`INSERT INTO api_endpoints (id, asset_id, method, path, parameters_json, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, method, path, JSON.stringify(parameters), source, new Date().toISOString(), new Date().toISOString())
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
    .prepare(`SELECT id, http_status, http_title, server_header, banner FROM services WHERE asset_id = ? AND port = ? AND protocol = ? AND removed_at IS NULL`)
    .bind(assetId, port, protocol)
    .first<{ id: string; http_status: number | null; http_title: string | null; server_header: string | null; banner: string | null }>();

  const changes: { field: string; before: string; after: string }[] = [];

  if (existing) {
    if (existing.http_status !== httpStatus) {
      changes.push({ field: "http_status", before: String(existing.http_status ?? "—"), after: String(httpStatus ?? "—") });
    }
    if ((existing.http_title ?? null) !== (httpTitle ?? null)) {
      changes.push({ field: "http_title", before: existing.http_title ?? "—", after: httpTitle ?? "—" });
    }
    if ((existing.server_header ?? null) !== (serverHeader ?? null)) {
      changes.push({ field: "server_header", before: existing.server_header ?? "—", after: serverHeader ?? "—" });
    }
    if ((existing.banner ?? null) !== (banner ?? null)) {
      changes.push({ field: "banner", before: existing.banner ?? "—", after: banner ?? "—" });
    }
    if (changes.length > 0) {
      await db
        .prepare(`UPDATE services SET http_status = ?, http_title = ?, server_header = ?, banner = ?, tls_json = ?, last_seen = ? WHERE id = ?`)
        .bind(httpStatus, httpTitle, serverHeader, banner, tlsJson, new Date().toISOString(), existing.id)
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
    .prepare(`INSERT INTO services (id, asset_id, port, protocol, banner, tls_json, http_status, http_title, server_header, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, port, protocol, banner, tlsJson, httpStatus, httpTitle, serverHeader, new Date().toISOString(), new Date().toISOString())
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
        .prepare(`UPDATE technologies SET version = ?, confidence = ?, source = ?, last_seen = ? WHERE id = ?`)
        .bind(version, confidence, source, new Date().toISOString(), existing.id)
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
    .prepare(`INSERT INTO technologies (id, asset_id, name, version, confidence, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, assetId, name, version, confidence, source, new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, created: true, versionChanged: false, previousVersion: null };
}
