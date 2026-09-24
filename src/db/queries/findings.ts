// src/db/queries/findings.ts
// Insert/list helpers for `findings` (migrations/0003_scans_findings.sql).
// Inserts are fingerprint-deduplicated: an already-known finding just gets
// its last_seen refreshed and is NOT re-alerted.

export interface FindingInsert {
  targetId: string;
  assetId?: string | null;
  findingType: string;
  title: string;
  summary: string;
  technicalDetail?: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  cveId?: string | null;
  cvssScore?: number | null;
  affectedAsset?: string;
  affectedUrl?: string | null;
  detectionSource: string;
  detectionMethod: string;
  confidence?: number;
  fingerprint: string;
  metadata?: Record<string, unknown>;
}

/**
 * Insert a finding keyed by (target_id, fingerprint). Returns the finding id
 * when newly created, or null when the same fingerprint was already recorded.
 */
export async function insertFinding(db: D1Database, f: FindingInsert): Promise<string | null> {
  const now = new Date().toISOString();
  const existing = await db
    .prepare(`SELECT id FROM findings WHERE target_id = ? AND fingerprint = ?`)
    .bind(f.targetId, f.fingerprint)
    .first<{ id: string }>();
  if (existing) {
    await db
      .prepare(`UPDATE findings SET last_seen = ?, updated_at = ? WHERE id = ?`)
      .bind(now, now, existing.id)
      .run();
    return null;
  }

  const id = `FND_${crypto.randomUUID()}`;
  await db
    .prepare(
      `INSERT INTO findings (
         id, finding_ref, organization_id, target_id, asset_id,
         finding_type, title, summary, technical_detail,
         severity, cve_id, cvss_score,
         affected_asset, affected_url,
         detection_source, detection_method, confidence,
         verification_state, status, fingerprint, metadata_json,
         first_seen, last_seen, created_at, updated_at
       ) VALUES (?, ?, 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'detected', 'open', ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id, id, f.targetId, f.assetId ?? null,
      f.findingType, f.title, f.summary, f.technicalDetail ?? null,
      f.severity, f.cveId ?? null, f.cvssScore ?? null,
      f.affectedAsset ?? f.affectedUrl ?? "", f.affectedUrl ?? null,
      f.detectionSource, f.detectionMethod, f.confidence ?? 0.8,
      f.fingerprint, JSON.stringify(f.metadata ?? {}),
      now, now, now, now,
    )
    .run();
  return id;
}

export async function listFindings(
  db: D1Database,
  targetId: string,
  limit = 20,
): Promise<Array<Record<string, unknown>>> {
  const rows = await db
    .prepare(`SELECT id, severity, title, cve_id, affected_url, first_seen FROM findings WHERE target_id = ? AND status = 'open' ORDER BY first_seen DESC LIMIT ?`)
    .bind(targetId, limit)
    .all<Record<string, unknown>>();
  return rows.results ?? [];
}
