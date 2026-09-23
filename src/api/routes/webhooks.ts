// src/api/routes/webhooks.ts
import type { RouteContext } from "../router.js";
import { jsonResponse, jsonError } from "../router.js";
import { verifyResultPayload, type RunnerResultPayload } from "../../providers/scanners/runner-protocol.js";
import { upsertAsset, upsertDnsRecord, upsertCertificate } from "../../db/queries/assets.js";
import { randomId } from "../../crypto/hash.js";
import { redactSync } from "../../security/redaction.js";

export async function handleRunnerCallback(ctx: RouteContext): Promise<Response> {
  // Verify the HMAC-signed result payload
  const body = (await ctx.request.json()) as RunnerResultPayload;
  const valid = await verifyResultPayload(body, ctx.env.API_HMAC_KEY);
  if (!valid) return jsonError(ctx.requestId, "invalid_signature", "Result signature verification failed", 401);

  // Look up the job
  const job = await ctx.env.DB
    .prepare(`SELECT * FROM scan_jobs WHERE id = ?`)
    .bind(body.job_id)
    .first<{ id: string; scan_id: string; organization_id: string; target_id: string; adapter: string }>();
  if (!job) return jsonError(ctx.requestId, "not_found", "Job not found", 404);

  // Update job status
  await ctx.env.DB
    .prepare(`UPDATE scan_jobs SET status = ?, finished_at = ?, result_summary = ? WHERE id = ?`)
    .bind(body.status, body.timestamp, `exit=${body.exit_code}; duration=${body.duration_seconds}s`, body.job_id)
    .run();

  // Persist findings as observations. All tool output is redacted before storage.
  const stdout = body.stdout_b64 ? atob(body.stdout_b64) : "";
  const { redacted } = redactSync(stdout);

  // Persist raw (redacted) output as evidence.
  // Uses R2 if bound, otherwise falls back to D1 evidence_blobs.
  const evidenceId = randomId("ev", 16);
  const r2Key = `evidence/runner/${body.job_id}/${evidenceId}`;
  const evidenceContent = JSON.stringify({
    tool: body.tool,
    exit_code: body.exit_code,
    duration_seconds: body.duration_seconds,
    stdout_redacted: redacted,
    artifacts: body.artifacts,
  });

  if (ctx.env.EVIDENCE) {
    await ctx.env.EVIDENCE.put(r2Key, evidenceContent, {
      customMetadata: {
        "job-id": body.job_id,
        "tool": body.tool,
        "created-at": body.timestamp,
      },
    });
  } else {
    // D1 fallback — store as encrypted blob.
    const { encryptString } = await import("../../crypto/encryption.js");
    const encrypted = await encryptString(evidenceContent, ctx.env.ENCRYPTION_KEY);
    const { sha256 } = await import("../../crypto/hash.js");
    const evidenceHash = await sha256(evidenceContent);
    await ctx.env.DB
      .prepare(`INSERT INTO evidence_blobs (id, r2_key, organization_id, target_id, finding_id, evidence_type, evidence_hash, encrypted_blob, redacted, description, created_at, accessed_at, access_count, expires_at) VALUES (?, ?, ?, ?, NULL, 'scanner_output', ?, ?, 1, ?, ?, NULL, 0, ?)`)
      .bind(
        evidenceId, r2Key,
        (await ctx.env.DB.prepare(`SELECT organization_id FROM targets WHERE id = ?`).bind(job.target_id).first<{ organization_id: string }>())?.organization_id ?? "",
        job.target_id,
        evidenceHash, encrypted,
        `Runner output for job ${body.job_id}`,
        new Date().toISOString(),
        new Date(Date.now() + 90 * 86_400_000).toISOString(),  // 90-day retention
      )
      .run();
  }

  await ctx.env.DB
    .prepare(`INSERT INTO scan_results (id, organization_id, target_id, scan_id, job_id, adapter, result_type, summary, payload_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, 'raw_output', ?, ?, ?)`)
    .bind(randomId("res", 12), job.organization_id, job.target_id, job.scan_id, body.job_id, body.tool, JSON.stringify({ exit_code: body.exit_code, duration_seconds: body.duration_seconds }), r2Key, new Date().toISOString())
    .run();

  return jsonResponse(ctx.requestId, { ok: true, job_id: body.job_id, status: body.status });
}
