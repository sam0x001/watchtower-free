// src/api/routes/reports.ts
import type { RouteContext } from "../router.js";
import { jsonResponse, jsonError } from "../router.js";
import { generateReport } from "../../modules/report-generator.js";
import { getTargetById } from "../../db/queries/targets.js";
import { listFindingsByOrg } from "../../db/queries/findings.js";

export async function generateReportRoute(ctx: RouteContext): Promise<Response> {
  const body = (await ctx.request.json()) as {
    target_id: string;
    format: "markdown" | "json" | "pdf" | "hackerone" | "bugcrowd" | "internal" | "executive";
    methodology?: string;
    tools?: string[];
    limitations?: string[];
    scope_text?: string;
  };
  const target = await getTargetById(ctx.env.DB, body.target_id);
  if (!target) return jsonError(ctx.requestId, "not_found", "Target not found", 404);
  const findings = await listFindingsByOrg(ctx.env.DB, target.organization_id, { limit: 500 });
  const report = await generateReport(ctx.env, {
    target,
    findings: findings.filter((f) => f.target_id === target.id),
    format: body.format,
    methodology: body.methodology ?? "Passive reconnaissance (CT logs, DNS-over-HTTPS, HTTP probing, JS analysis) plus external-runner-based scanning with allowlisted tools. No intrusive testing performed without human approval.",
    tools: body.tools ?? ["crt.sh", "Cert Spotter", "crtndstry", "Cloudflare DNS-over-HTTPS", "httpx (Worker)", "Subfinder", "Amass", "Nuclei (external runner)"],
    limitations: body.limitations ?? [
      "Cloudflare Workers cannot execute native binaries; all heavy scanning runs through authorized external runners.",
      "JavaScript analysis is regex-based when parsing fails; results are lower-confidence.",
      "Secret candidates are never validated automatically; manual verification required.",
    ],
    scopeText: body.scope_text ?? `Target ${target.name} (authorized via ${target.authorization_reference}, expires ${target.authorization_expires_at}).`,
    authorized: true,
  });
  return jsonResponse(ctx.requestId, { report });
}
