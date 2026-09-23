// src/db/queries/findings.ts

import type { Finding } from "../../types.js";

export async function insertFinding(db: D1Database, f: Finding): Promise<void> {
  await db
    .prepare(`INSERT INTO findings (
      id, finding_ref, organization_id, target_id, asset_id,
      finding_type, title, summary, technical_detail, business_impact,
      severity, cvss_score, cvss_vector, epss_score, cwe_id, cve_id,
      owasp_category, affected_asset, affected_url,
      detection_source, detection_method, confidence, status,
      assigned_user_id, verification_state, scope_validation,
      remediation, retest_status, duplicate_of, attack_chain_id,
      priority_score, first_seen, last_seen, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      f.id, f.id, f.organization_id, f.target_id, f.asset_id,
      f.type, f.title, f.summary, f.technical_description, f.business_impact,
      f.severity, f.cvss_score, f.cvss_vector, f.epss_score, f.cwe, f.cve,
      f.owasp_category, f.affected_url ?? "", f.affected_url,
      f.detection_source, f.detection_method, f.confidence, f.status,
      f.assigned_user_id, f.verification_state, f.scope_validation_state,
      f.remediation, f.retest_status, f.duplicate_of, f.attack_chain_id,
      0, f.first_seen, f.last_seen, f.created_at, f.updated_at,
    )
    .run();
}

export async function getFindingById(db: D1Database, id: string): Promise<Finding | null> {
  const r = await db.prepare(`SELECT * FROM findings WHERE id = ?`).bind(id).first<Record<string, unknown>>();
  return r ? rowToFinding(r) : null;
}

export async function listFindingsByOrg(
  db: D1Database,
  orgId: string,
  opts: { limit?: number; offset?: number; status?: string; severity?: string } = {},
): Promise<Finding[]> {
  const limit = Math.min(Math.max(1, opts.limit ?? 50), 200);
  const offset = Math.max(0, opts.offset ?? 0);
  const where: string[] = ["organization_id = ?"];
  const binds: (string | number)[] = [orgId];
  if (opts.status) { where.push("status = ?"); binds.push(opts.status); }
  if (opts.severity) { where.push("severity = ?"); binds.push(opts.severity); }
  const rows = await db
    .prepare(`SELECT * FROM findings WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .bind(...binds, limit, offset)
    .all<Record<string, unknown>>();
  return (rows.results ?? []).map(rowToFinding);
}

export async function updateFindingStatus(
  db: D1Database,
  findingId: string,
  status: Finding["status"],
  verificationState?: Finding["verification_state"],
): Promise<void> {
  if (verificationState) {
    await db
      .prepare(`UPDATE findings SET status = ?, verification_state = ?, updated_at = ?, last_seen = ? WHERE id = ?`)
      .bind(status, verificationState, new Date().toISOString(), new Date().toISOString(), findingId)
      .run();
  } else {
    await db
      .prepare(`UPDATE findings SET status = ?, updated_at = ? WHERE id = ?`)
      .bind(status, new Date().toISOString(), findingId)
      .run();
  }
}

export async function assignFinding(db: D1Database, findingId: string, userId: string): Promise<void> {
  await db
    .prepare(`UPDATE findings SET assigned_user_id = ?, status = 'triaged', updated_at = ? WHERE id = ?`)
    .bind(userId, new Date().toISOString(), findingId)
    .run();
}

export async function markDuplicate(db: D1Database, findingId: string, primaryId: string): Promise<void> {
  await db
    .prepare(`UPDATE findings SET duplicate_of = ?, status = 'closed', verification_state = 'false_positive', updated_at = ? WHERE id = ?`)
    .bind(primaryId, new Date().toISOString(), findingId)
    .run();
}

function rowToFinding(r: Record<string, unknown>): Finding {
  return {
    id: String(r["id"]),
    organization_id: String(r["organization_id"]),
    target_id: String(r["target_id"]),
    asset_id: (r["asset_id"] as string | null) ?? null,
    type: String(r["type"]),
    title: String(r["title"]),
    summary: String(r["summary"]),
    technical_description: String(r["technical_description"] ?? ""),
    business_impact: (r["business_impact"] as string | null) ?? null,
    severity: r["severity"] as Finding["severity"],
    cvss_score: (r["cvss_score"] as number | null) ?? null,
    cvss_vector: (r["cvss_vector"] as string | null) ?? null,
    epss_score: (r["epss_score"] as number | null) ?? null,
    cwe: (r["cwe"] as string | null) ?? null,
    cve: (r["cve"] as string | null) ?? null,
    owasp_category: (r["owasp_category"] as string | null) ?? null,
    affected_url: (r["affected_url"] as string | null) ?? null,
    detection_source: String(r["detection_source"]),
    detection_method: String(r["detection_method"]),
    confidence: Number(r["confidence"] ?? 0.5),
    status: r["status"] as Finding["status"],
    assigned_user_id: (r["assigned_user_id"] as string | null) ?? null,
    verification_state: r["verification_state"] as Finding["verification_state"],
    scope_validation_state: r["scope_validation_state"] as Finding["scope_validation_state"],
    remediation: (r["remediation"] as string | null) ?? null,
    retest_status: (r["retest_status"] as Finding["retest_status"] | null) ?? null,
    duplicate_of: (r["duplicate_of"] as string | null) ?? null,
    attack_chain_id: (r["attack_chain_id"] as string | null) ?? null,
    first_seen: String(r["first_seen"]),
    last_seen: String(r["last_seen"]),
    created_at: String(r["created_at"]),
    updated_at: String(r["updated_at"]),
  };
}
