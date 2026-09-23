// src/api/router.ts
// REST API router. Versioned under /v1/. Auth via Bearer tokens (HMAC-signed).
// All routes are audit-logged. Scope is validated on every mutating request.

import type { Env } from "../env.js";
import type { ApiResponse } from "../types.js";
import { verifyToken } from "../crypto/hmac.js";
import { newRequestId, D1AuditLogger } from "../audit/logger.js";
import { log } from "../audit/logger.js";
import { listFindingsByOrg, getFindingById, updateFindingStatus, assignFinding } from "../db/queries/findings.js";
import { getTargetById, listTargets, listScopeEntries } from "../db/queries/targets.js";
import { listEvidence, signedEvidenceUrl } from "../evidence/r2-storage.js";
import { generateReport } from "../modules/report-generator.js";
import { listAuditLogs } from "../db/queries/audit.js";
import { generateReportRoute } from "./routes/reports.js";
import { handleRunnerCallback } from "./routes/webhooks.js";

export interface RouteContext {
  env: Env;
  request: Request;
  url: URL;
  requestId: string;
  userId: string | null;
  orgId: string | null;
  audit: D1AuditLogger;
}

type Handler = (ctx: RouteContext) => Promise<Response>;

const routes: { pattern: RegExp; method: string; handler: Handler; requiresAuth: boolean }[] = [
  { pattern: /^\/v1\/health$/, method: "GET", handler: healthHandler, requiresAuth: false },
  { pattern: /^\/v1\/targets$/, method: "GET", handler: listTargetsHandler, requiresAuth: true },
  { pattern: /^\/v1\/targets\/([^/]+)$/, method: "GET", handler: getTargetHandler, requiresAuth: true },
  { pattern: /^\/v1\/targets\/([^/]+)\/scope$/, method: "GET", handler: getTargetScopeHandler, requiresAuth: true },
  { pattern: /^\/v1\/findings$/, method: "GET", handler: listFindingsHandler, requiresAuth: true },
  { pattern: /^\/v1\/findings\/([^/]+)$/, method: "GET", handler: getFindingHandler, requiresAuth: true },
  { pattern: /^\/v1\/findings\/([^/]+)\/status$/, method: "PATCH", handler: patchFindingStatusHandler, requiresAuth: true },
  { pattern: /^\/v1\/findings\/([^/]+)\/assign$/, method: "POST", handler: assignFindingHandler, requiresAuth: true },
  { pattern: /^\/v1\/reports$/, method: "POST", handler: generateReportRoute, requiresAuth: true },
  { pattern: /^\/v1\/evidence$/, method: "GET", handler: listEvidenceHandler, requiresAuth: true },
  { pattern: /^\/v1\/evidence\/download$/, method: "GET", handler: downloadEvidenceHandler, requiresAuth: true },
  { pattern: /^\/v1\/audit$/, method: "GET", handler: listAuditHandler, requiresAuth: true },
  { pattern: /^\/v1\/runner\/callback$/, method: "POST", handler: handleRunnerCallback, requiresAuth: false },
];

export async function routeApi(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const requestId = newRequestId();
  const audit = new D1AuditLogger(env.DB);

  for (const r of routes) {
    if (r.method !== request.method) continue;
    const m = url.pathname.match(r.pattern);
    if (!m) continue;

    let userId: string | null = null;
    let orgId: string | null = null;

    if (r.requiresAuth) {
      const auth = request.headers.get("authorization") ?? "";
      if (!auth.startsWith("Bearer ")) {
        return jsonError(requestId, "missing_bearer_token", "Authorization required", 401);
      }
      const token = auth.slice(7);
      const claims = await verifyToken(env.API_HMAC_KEY, token);
      if (!claims) {
        return jsonError(requestId, "invalid_token", "Token verification failed", 401);
      }
      userId = (claims["sub"] as string) ?? null;
      orgId = (claims["org"] as string) ?? null;
    }

    const ctx: RouteContext = { env, request, url, requestId, userId, orgId, audit };
    try {
      const response = await r.handler(ctx);
      await audit.log({
        timestamp: new Date().toISOString(),
        user_id: userId,
        telegram_id: null,
        actor_kind: "api",
        organization_id: orgId,
        action: `api.${request.method}.${url.pathname}`,
        target_id: null,
        scope_id: null,
        job_id: null,
        scanner: null,
        args_redacted: "{}",
        result: response.ok ? "success" : "failure",
        error: response.ok ? null : `HTTP ${response.status}`,
        ip: request.headers.get("cf-connecting-ip"),
        request_id: requestId,
      });
      return response;
    } catch (err) {
      log.error("api.route_error", { path: url.pathname, err: String(err), requestId });
      await audit.log({
        timestamp: new Date().toISOString(),
        user_id: userId, telegram_id: null, actor_kind: "api", organization_id: orgId,
        action: `api.${request.method}.${url.pathname}`,
        target_id: null, scope_id: null, job_id: null, scanner: null,
        args_redacted: "{}",
        result: "failure",
        error: String(err),
        ip: request.headers.get("cf-connecting-ip"),
        request_id: requestId,
      });
      return jsonError(requestId, "internal_error", String(err), 500);
    }
  }

  return jsonError(requestId, "not_found", `No route for ${request.method} ${url.pathname}`, 404);
}

function jsonError(requestId: string, code: string, message: string, status: number): Response {
  const body: ApiResponse<never> = { ok: false, error: { code, message }, request_id: requestId };
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function jsonResponse<T>(requestId: string, data: T, status = 200): Response {
  const body: ApiResponse<T> = { ok: true, data, request_id: requestId };
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function healthHandler(_ctx: RouteContext): Promise<Response> {
  return jsonResponse(_ctx.requestId, { status: "ok", version: "1.0.0", time: new Date().toISOString() });
}

async function listTargetsHandler(ctx: RouteContext): Promise<Response> {
  if (!ctx.orgId) return jsonError(ctx.requestId, "missing_org", "Organization required", 400);
  const targets = await listTargets(ctx.env.DB, ctx.orgId);
  return jsonResponse(ctx.requestId, { targets });
}

async function getTargetHandler(ctx: RouteContext): Promise<Response> {
  const id = ctx.url.pathname.match(/^\/v1\/targets\/([^/]+)$/)![1]!;
  const t = await getTargetById(ctx.env.DB, id);
  if (!t) return jsonError(ctx.requestId, "not_found", "Target not found", 404);
  return jsonResponse(ctx.requestId, { target: t });
}

async function getTargetScopeHandler(ctx: RouteContext): Promise<Response> {
  const id = ctx.url.pathname.match(/^\/v1\/targets\/([^/]+)\/scope$/)![1]!;
  const entries = await listScopeEntries(ctx.env.DB, id);
  return jsonResponse(ctx.requestId, { scope: entries });
}

async function listFindingsHandler(ctx: RouteContext): Promise<Response> {
  if (!ctx.orgId) return jsonError(ctx.requestId, "missing_org", "Organization required", 400);
  const findings = await listFindingsByOrg(ctx.env.DB, ctx.orgId, {
    limit: Number(ctx.url.searchParams.get("limit") ?? 50),
    offset: Number(ctx.url.searchParams.get("offset") ?? 0),
    status: ctx.url.searchParams.get("status") ?? undefined,
    severity: ctx.url.searchParams.get("severity") ?? undefined,
  });
  return jsonResponse(ctx.requestId, { findings });
}

async function getFindingHandler(ctx: RouteContext): Promise<Response> {
  const id = ctx.url.pathname.match(/^\/v1\/findings\/([^/]+)$/)![1]!;
  const f = await getFindingById(ctx.env.DB, id);
  if (!f) return jsonError(ctx.requestId, "not_found", "Finding not found", 404);
  return jsonResponse(ctx.requestId, { finding: f });
}

async function patchFindingStatusHandler(ctx: RouteContext): Promise<Response> {
  const id = ctx.url.pathname.match(/^\/v1\/findings\/([^/]+)\/status$/)![1]!;
  const body = (await ctx.request.json()) as { status: string; verification_state?: string };
  await updateFindingStatus(ctx.env.DB, id, body.status as never, body.verification_state as never);
  return jsonResponse(ctx.requestId, { ok: true });
}

async function assignFindingHandler(ctx: RouteContext): Promise<Response> {
  const id = ctx.url.pathname.match(/^\/v1\/findings\/([^/]+)\/assign$/)![1]!;
  const body = (await ctx.request.json()) as { user_id: string };
  await assignFinding(ctx.env.DB, id, body.user_id);
  return jsonResponse(ctx.requestId, { ok: true });
}

async function listEvidenceHandler(ctx: RouteContext): Promise<Response> {
  if (!ctx.orgId) return jsonError(ctx.requestId, "missing_org", "Organization required", 400);
  const findingId = ctx.url.searchParams.get("finding_id") ?? undefined;
  const evidence = await listEvidence(ctx.env, { organizationId: ctx.orgId, findingId, limit: Number(ctx.url.searchParams.get("limit") ?? 50), offset: Number(ctx.url.searchParams.get("offset") ?? 0) });
  return jsonResponse(ctx.requestId, { evidence });
}

async function downloadEvidenceHandler(ctx: RouteContext): Promise<Response> {
  const key = ctx.url.searchParams.get("key");
  if (!key) return jsonError(ctx.requestId, "missing_key", "Evidence key required", 400);
  const sig = ctx.url.searchParams.get("sig");
  const expires = ctx.url.searchParams.get("expires");
  if (!sig || !expires) return jsonError(ctx.requestId, "missing_signature", "Signature required", 400);
  // Verify signature
  const expectedSig = await hmacSign(ctx.env.API_HMAC_KEY, `${key}.${expires}`);
  if (expectedSig !== sig) return jsonError(ctx.requestId, "invalid_signature", "Bad signature", 401);
  if (new Date(expires).getTime() < Date.now()) return jsonError(ctx.requestId, "expired", "URL expired", 401);

  // Try R2 first if bound, otherwise fall back to D1 evidence_blobs.
  if (ctx.env.EVIDENCE) {
    const obj = await ctx.env.EVIDENCE.get(key);
    if (!obj) return jsonError(ctx.requestId, "not_found", "Evidence not found", 404);
    const body = await obj.text();
    return new Response(body, { headers: { "content-type": "application/octet-stream", "x-evidence-key": key } });
  }

  // D1 fallback: retrieve + decrypt the evidence blob.
  const row = await ctx.env.DB
    .prepare(`SELECT encrypted_blob FROM evidence_blobs WHERE r2_key = ?`)
    .bind(key)
    .first<{ encrypted_blob: string }>();
  if (!row) return jsonError(ctx.requestId, "not_found", "Evidence not found", 404);
  // Update access tracking
  await ctx.env.DB
    .prepare(`UPDATE evidence_blobs SET accessed_at = ?, access_count = access_count + 1 WHERE r2_key = ?`)
    .bind(new Date().toISOString(), key)
    .run()
    .catch(() => undefined);
  return new Response(row.encrypted_blob, {
    headers: { "content-type": "application/octet-stream", "x-evidence-key": key },
  });
}

async function hmacSign(key: string, msg: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function listAuditHandler(ctx: RouteContext): Promise<Response> {
  if (!ctx.orgId) return jsonError(ctx.requestId, "missing_org", "Organization required", 400);
  const logs = await listAuditLogs(ctx.env.DB, ctx.orgId, {
    limit: Number(ctx.url.searchParams.get("limit") ?? 100),
    offset: Number(ctx.url.searchParams.get("offset") ?? 0),
    action: ctx.url.searchParams.get("action") ?? undefined,
  });
  return jsonResponse(ctx.requestId, { audit: logs });
}

export { jsonResponse, jsonError };
