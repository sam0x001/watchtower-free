// src/evidence/d1-storage.ts
// D1-backed evidence storage — replaces R2 for the free tier.
//
// Why D1 instead of R2:
//   - R2 requires a payment method on file (even though the 10 GB free tier
//     is technically free)
//   - D1's 5 GB free storage doesn't require payment method
//   - Evidence is already AES-GCM encrypted before storage, so storing as
//     TEXT in a D1 table is fine
//
// Each evidence record gets:
//   - id (TEXT PRIMARY KEY)
//   - r2_key (TEXT) — kept for backward compat with the old R2-style API
//   - organization_id, target_id, finding_id (TEXT)
//   - evidence_type (TEXT)
//   - evidence_hash (TEXT)
//   - encrypted_blob (TEXT) — AES-GCM ciphertext as base64
//   - redacted (INTEGER 0/1)
//   - description (TEXT)
//   - created_at, accessed_at (TEXT)
//   - access_count (INTEGER)
//   - expires_at (TEXT) — for retention enforcement

import type { Env } from "../env.js";
import { encryptString, decryptString, secretFingerprint } from "../crypto/encryption.js";
import { sha256 } from "../crypto/hash.js";
import { randomId } from "../crypto/hash.js";

export interface StoreEvidenceOpts {
  organizationId: string;
  targetId: string;
  findingId?: string;
  evidenceType: "http_request" | "http_response" | "dns_response" | "tls_certificate" | "javascript_snapshot" | "scanner_output" | "screenshot" | "dom_snapshot";
  content: string | Uint8Array;
  description?: string;
  retentionDays: number;
  redacted?: boolean;
}

export interface StoredEvidence {
  id: string;
  r2Key: string;       // backward-compat name; actually the D1 row key
  evidenceHash: string;
  createdAt: string;
  expiresAt: string;
}

export async function storeEvidence(env: Env, opts: StoreEvidenceOpts): Promise<StoredEvidence> {
  const content = typeof opts.content === "string" ? opts.content : new TextDecoder().decode(opts.content);
  const encrypted = await encryptString(content, env.ENCRYPTION_KEY);
  const evidenceHash = await sha256(content);
  const id = randomId("ev", 16);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + opts.retentionDays * 86_400_000).toISOString();
  // We keep the `r2Key` shape for backward compat — it's now just a path
  // identifier used to look up the row in `evidence_blobs`.
  const r2Key = `evidence/${opts.organizationId}/${opts.targetId}/${opts.findingId ?? "unassigned"}/${id}`;

  await env.DB
    .prepare(`INSERT INTO evidence_blobs (
      id, r2_key, organization_id, target_id, finding_id, evidence_type,
      evidence_hash, encrypted_blob, redacted, description, created_at,
      accessed_at, access_count, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?)`)
    .bind(
      id, r2Key, opts.organizationId, opts.targetId, opts.findingId ?? null,
      opts.evidenceType, evidenceHash, encrypted,
      opts.redacted === false ? 0 : 1, opts.description ?? "",
      now.toISOString(), expiresAt,
    )
    .run();

  // Also keep the legacy `finding_evidence` row in sync so existing API
  // consumers that join on that table keep working.
  if (opts.findingId) {
    await env.DB
      .prepare(`INSERT INTO finding_evidence (id, organization_id, target_id, finding_id, evidence_type, r2_key, content_hash, encrypted, encryption_alg, key_version, size_bytes, redacted, captured_by, capture_method, captured_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'AES-256-GCM', 'v1', 0, ?, 'worker', 'd1-storage', ?, ?)`)
      .bind(id, opts.organizationId, opts.targetId, opts.findingId ?? null, opts.evidenceType, r2Key, evidenceHash, opts.redacted === false ? 0 : 1, now.toISOString(), now.toISOString())
      .run();
  }

  return { id, r2Key, evidenceHash, createdAt: now.toISOString(), expiresAt };
}

export async function retrieveEvidence(
  env: Env,
  r2Key: string,
  expectedHash: string | null,
  accessUserId: string | null,
): Promise<{ content: string; verified: boolean; fingerprint: string }> {
  const row = await env.DB
    .prepare(`SELECT encrypted_blob, evidence_hash FROM evidence_blobs WHERE r2_key = ?`)
    .bind(r2Key)
    .first<{ encrypted_blob: string; evidence_hash: string }>();
  if (!row) throw new Error("evidence not found");

  let content: string;
  try {
    content = await decryptString(row.encrypted_blob, env.ENCRYPTION_KEY);
  } catch (err) {
    throw new Error(`evidence decryption failed: ${String(err)}`);
  }

  const actualHash = await sha256(content);
  const verified = expectedHash ? actualHash === expectedHash : true;

  // Update access log
  await env.DB
    .prepare(`UPDATE evidence_blobs SET accessed_at = ?, access_count = access_count + 1 WHERE r2_key = ?`)
    .bind(new Date().toISOString(), r2Key)
    .run();
  await env.DB
    .prepare(`UPDATE finding_evidence SET verified_at = ? WHERE r2_key = ?`)
    .bind(new Date().toISOString(), r2Key)
    .run()
    .catch(() => undefined);

  const fingerprint = await secretFingerprint(content);
  return { content, verified, fingerprint };
}

/**
 * Generates a short-lived signed URL for downloading evidence outside the Worker.
 * On the free tier, this URL still points at the Worker's REST endpoint
 * `/v1/evidence/download?key=...&sig=...&expires=...` — there's no separate
 * R2 presigned URL.
 */
export async function signedEvidenceUrl(
  env: Env,
  r2Key: string,
  ttlSeconds = 300,
): Promise<{ url: string; expiresAt: string }> {
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const payload = `${r2Key}.${expiresAt}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(env.API_HMAC_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const params = new URLSearchParams({ key: r2Key, expires: expiresAt, sig: sigHex });
  // On the free tier, the URL points at the deployed Worker itself.
  // Operators replace the host with their own.
  return {
    url: `https://watchtower.example.workers.dev/v1/evidence/download?${params}`,
    expiresAt,
  };
}

export interface EvidenceListOpts {
  findingId?: string;
  organizationId: string;
  limit?: number;
  offset?: number;
}

export async function listEvidence(env: Env, opts: EvidenceListOpts): Promise<{ id: string; r2Key: string; evidenceType: string; evidenceHash: string; createdAt: string }[]> {
  const limit = Math.min(Math.max(1, opts.limit ?? 50), 200);
  const offset = Math.max(0, opts.offset ?? 0);
  if (opts.findingId) {
    const rows = await env.DB
      .prepare(`SELECT id, r2_key, evidence_type, content_hash AS evidence_hash, created_at FROM finding_evidence WHERE finding_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(opts.findingId, limit, offset)
      .all<Record<string, unknown>>();
    return (rows.results ?? []).map(rowToEvidence);
  }
  return [];
}

function rowToEvidence(r: Record<string, unknown>) {
  return {
    id: String(r["id"]),
    r2Key: String(r["evidence_key"] ?? r["r2_key"] ?? ""),
    evidenceType: String(r["evidence_type"]),
    evidenceHash: String(r["evidence_hash"]),
    createdAt: String(r["created_at"]),
  };
}

/**
 * Purge expired evidence rows (called from cron hourly).
 * Returns the count of rows deleted.
 */
export async function purgeExpiredEvidence(env: Env): Promise<number> {
  const now = new Date().toISOString();
  const result = await env.DB
    .prepare(`DELETE FROM evidence_blobs WHERE expires_at < ?`)
    .bind(now)
    .run();
  // Also clean up finding_evidence rows whose evidence_blobs row was purged.
  await env.DB
    .prepare(`DELETE FROM finding_evidence WHERE r2_key NOT IN (SELECT r2_key FROM evidence_blobs)`)
    .run()
    .catch(() => undefined);
  return result.meta?.changes ?? 0;
}
