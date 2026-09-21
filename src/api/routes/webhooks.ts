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
    .first<{ id: string; scan_id: string; target_id: string; tool: string }>();
  if (!job) return jsonError(ctx.requestId, "not_found", "Job not found", 404);

  // Update job status
  await ctx.env.DB
    .prepare(`UPDATE scan_jobs SET status = ?, completed_at = ?, result_summary = ? WHERE id = ?`)
    .bind(body.status, body.timestamp, `exit=${body.exit_code}; duration=${body.duration_seconds}s`, body.job_id)
    .run();

  // Persist findings as observations. All tool output is redacted before storage.
  const stdout = body.stdout_b64 ? atob(body.stdout_b64) : "";
  const { redacted } = redactSync(stdout);

  // Persist raw (redacted) output as evidence
  const evidenceId = randomId("ev", 16);
  const r2Key = `evidence/runner/${body.job_id}/${evidenceId}`;
  await ctx.env.EVIDENCE.put(r2Key, JSON.stringify({
    tool: body.tool,
    exit_code: body.exit_code,
    duration_seconds: body.duration_seconds,
    stdout_redacted: redacted,
    artifacts: body.artifacts,
  }), {
    customMetadata: {
      "job-id": body.job_id,
      "tool": body.tool,
      "created-at": body.timestamp,
    },
  });

  await ctx.env.DB
    .prepare(`INSERT INTO scan_results (id, scan_id, asset_id, tool, result_type, payload_json, evidence_key, created_at) VALUES (?, ?, NULL, ?, 'raw_output', ?, ?, ?)`)
    .bind(randomId("res", 12), job.scan_id, body.tool, JSON.stringify({ exit_code: body.exit_code, duration_seconds: body.duration_seconds }), r2Key, new Date().toISOString())
    .run();

  return jsonResponse(ctx.requestId, { ok: true, job_id: body.job_id, status: body.status });
}
