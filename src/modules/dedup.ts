// src/modules/dedup.ts
// Finding deduplication. Normalizes URLs, hostnames, ports, paths, vulnerability
// templates, compares fingerprints and evidence hashes. Allows manual split/merge.

import type { Finding } from "../types.js";
import { canonicalizeUrl } from "../utils/url.js";
import { normalizeDomain } from "../utils/domain.js";
import { sha256 } from "../crypto/hash.js";

export interface FindingFingerprint {
  fingerprint: string;
  components: {
    type: string;
    host: string | null;
    path: string | null;
    port: number | null;
    cve: string | null;
    cwe: string | null;
    detection_source: string;
    evidence_hash: string | null;
  };
}

export async function fingerprintFinding(f: Partial<Finding>): Promise<FindingFingerprint> {
  const host = f.affected_url ? normalizeDomain(new URL(f.affected_url).hostname) ?? null : null;
  const port = f.affected_url ? (() => { try { return new URL(f.affected_url!).port ? Number(new URL(f.affected_url!).port) : (new URL(f.affected_url!).protocol === "https:" ? 443 : 80); } catch { return null; } })() : null;
  let path: string | null = null;
  if (f.affected_url) {
    const canon = canonicalizeUrl(f.affected_url);
    if (canon) {
      try { path = new URL(canon).pathname; } catch { path = null; }
    }
  }
  const components = {
    type: f.type ?? "",
    host: host ?? "",
    path: path ?? "",
    port: port ?? 0,
    cve: f.cve ?? "",
    cwe: f.cwe ?? "",
    detection_source: f.detection_source ?? "",
    evidence_hash: null as string | null,
  };
  const fp = await sha256(JSON.stringify(components));
  return { fingerprint: fp, components };
}

/**
 * Returns a list of duplicate finding IDs given a new finding's fingerprint.
 */
export async function findDuplicates(
  db: D1Database,
  orgId: string,
  fp: FindingFingerprint,
): Promise<string[]> {
  // We don't store the fingerprint directly in the schema for v1; compute on demand.
  // For large datasets, add an index on a fingerprint column.
  const rows = await db
    .prepare(`SELECT id, type, affected_url, cve, cwe, detection_source FROM findings WHERE organization_id = ? AND status NOT IN ('closed')`)
    .bind(orgId)
    .all<Record<string, unknown>>();
  const dupes: string[] = [];
  for (const r of rows.results ?? []) {
    if (r["type"] !== fp.components.type) continue;
    if (r["cve"] !== fp.components.cve) continue;
    if (r["cwe"] !== fp.components.cwe) continue;
    if (r["detection_source"] !== fp.components.detection_source) continue;
    const theirUrl = (r["affected_url"] as string | null) ?? "";
    const canon = canonicalizeUrl(theirUrl);
    if (canon) {
      try {
        const theirHost = normalizeDomain(new URL(canon).hostname);
        const theirPath = new URL(canon).pathname;
        if (theirHost === fp.components.host && theirPath === fp.components.path) {
          dupes.push(String(r["id"]));
        }
      } catch { /* ignore */ }
    }
  }
  return dupes;
}

export async function mergeFindings(db: D1Database, primaryId: string, duplicateId: string): Promise<void> {
  await db.prepare(`UPDATE findings SET duplicate_of = ?, status = 'closed', verification_state = 'false_positive', updated_at = ? WHERE id = ?`)
    .bind(primaryId, new Date().toISOString(), duplicateId).run();
  await db.prepare(`UPDATE finding_evidence SET finding_id = ? WHERE finding_id = ?`)
    .bind(primaryId, duplicateId).run();
  await db.prepare(`UPDATE finding_comments SET finding_id = ? WHERE finding_id = ?`)
    .bind(primaryId, duplicateId).run();
}

export async function splitFinding(db: D1Database, findingId: string): Promise<string> {
  const original = await db.prepare(`SELECT * FROM findings WHERE id = ?`).bind(findingId).first<Record<string, unknown>>();
  if (!original) throw new Error("finding not found");
  const newId = `FND_${crypto.randomUUID()}`;
  await db.prepare(`INSERT INTO findings (
    id, organization_id, target_id, asset_id, type, title, summary,
    technical_description, business_impact, severity, cvss_score, cvss_vector,
    epss_score, cwe, cve, owasp_category, affected_url,
    detection_source, detection_method, confidence, status,
    assigned_user_id, verification_state, scope_validation_state,
    remediation, retest_status, duplicate_of, attack_chain_id,
    priority_score, first_seen, last_seen, created_at, updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, 'detected', 'pending', NULL, NULL, NULL, NULL, 0, ?, ?, ?, ?)`)
    .bind(
      newId,
      original["organization_id"], original["target_id"], original["asset_id"],
      original["type"], original["title"], original["summary"],
      original["technical_description"], original["business_impact"], original["severity"],
      original["cvss_score"], original["cvss_vector"], original["epss_score"],
      original["cwe"], original["cve"], original["owasp_category"], original["affected_url"],
      original["detection_source"], original["detection_method"], original["confidence"],
      new Date().toISOString(), new Date().toISOString(), new Date().toISOString(), new Date().toISOString(),
    ).run();
  return newId;
}
