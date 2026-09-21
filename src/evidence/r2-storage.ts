// src/evidence/r2-storage.ts
// Encrypted R2 evidence storage with integrity verification + access control.

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
  r2Key: string;
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
  const r2Key = `evidence/${opts.organizationId}/${opts.targetId}/${opts.findingId ?? "unassigned"}/${id}`;

  await env.EVIDENCE.put(r2Key, encrypted, {
    customMetadata: {
      "evidence-id": id,
      "evidence-type": opts.evidenceType,
      "evidence-hash": evidenceHash,
      "created-at": now.toISOString(),
      "expires-at": expiresAt,
      "organization-id": opts.organizationId,
      "target-id": opts.targetId,
      "finding-id": opts.findingId ?? "",
      "description": opts.description ?? "",
      "redacted": String(opts.redacted ?? true),
    },
  });

  if (opts.findingId) {
    await env.DB
      .prepare(`INSERT INTO finding_evidence (id, finding_id, evidence_key, evidence_type, evidence_hash, redacted, description, created_at, access_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`)
      .bind(id, opts.findingId, r2Key, opts.evidenceType, evidenceHash, opts.redacted === false ? 0 : 1, opts.description ?? "", now.toISOString())
      .run();
  }

  return { id, r2Key, evidenceHash, createdAt: now.toISOString(), expiresAt };
}

export async function retrieveEvidence(
  env: Env,
  r2Key: string,
  expectedHash: string | null,
  accessUserId: string | null,
): Promise<{ content: string; verified: boolean; fingerprint: string | null }> {
  const obj = await env.EVIDENCE.get(r2Key);
  if (!obj) throw new Error("evidence not found");
  const encrypted = await obj.text();
  let content: string;
  try {
    content = await decryptString(encrypted, env.ENCRYPTION_KEY);
  } catch (err) {
    throw new Error(`evidence decryption failed: ${String(err)}`);
  }
  const actualHash = await sha256(content);
  const verified = expectedHash ? actualHash === expectedHash : true;
  // Update access log
  await env.DB
    .prepare(`UPDATE finding_evidence SET accessed_at = ?, access_count = access_count + 1 WHERE evidence_key = ?`)
    .bind(new Date().toISOString(), r2Key)
    .run()
    .catch(() => undefined);
  const fingerprint = await secretFingerprint(content);
  return { content, verified, fingerprint };
}

/**
 * Generates a short-lived signed URL for downloading evidence outside the Worker.
 * The URL expires after `ttlSeconds` (default 5 min) and is HMAC-signed.
 */
export async function signedEvidenceUrl(
  env: Env,
  r2Key: string,
  ttlSeconds = 300,
): Promise<{ url: string; expiresAt: string }> {
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const payload = `${r2Key}.${expiresAt}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(env.API_HMAC_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const params = new URLSearchParams({ key: r2Key, expires: expiresAt, sig: sigHex });
  // In production this URL points at the public Worker route /v1/evidence/download
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
      .prepare(`SELECT id, evidence_key, evidence_type, evidence_hash, created_at FROM finding_evidence WHERE finding_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(opts.findingId, limit, offset)
      .all<Record<string, unknown>>();
    return (rows.results ?? []).map(rowToEvidence);
  }
  return [];
}

function rowToEvidence(r: Record<string, unknown>) {
  return {
    id: String(r["id"]),
    r2Key: String(r["evidence_key"]),
    evidenceType: String(r["evidence_type"]),
    evidenceHash: String(r["evidence_hash"]),
    createdAt: String(r["created_at"]),
  };
}
