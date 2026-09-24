// src/providers/cve/osv.ts
// OSV.dev CVE lookup — correlates detected software versions to known
// vulnerabilities. Query-only: no exploit attempts, results are advisory.
//
// Includes a real CVSS 3.1 base-score calculator so severities are accurate
// instead of hardcoded.

import type { ProviderContext } from "../types.js";
import { LIMITS } from "../../constants.js";

export interface CveLookup {
  cve: string | null;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  cvss_score: number | null;
  cvss_vector: string | null;
  fixed_version: string | null;
  references: string[];
}

const OSV_URL = "https://api.osv.dev/v1/query";

export class OsvProvider {
  async lookup(
    ecosystem: string,
    packageName: string,
    version: string,
    ctx: Pick<ProviderContext, "timeoutMs">,
  ): Promise<CveLookup[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(ctx.timeoutMs, LIMITS.MAX_REQUEST_TIMEOUT_MS));
    try {
      const resp = await fetch(OSV_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: { name: packageName, ecosystem }, version }),
        signal: controller.signal,
      });
      if (!resp.ok) return [];
      const text = await readBounded(resp, LIMITS.MAX_RESPONSE_BYTES);
      let body: {
        vulns?: Array<{
          id?: string;
          summary?: string;
          severity?: Array<{ score?: string; type?: string }>;
          references?: Array<{ url?: string }>;
          affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }>;
        }>;
      };
      try { body = JSON.parse(text); } catch { return []; }

      const out: CveLookup[] = [];
      for (const v of body.vulns ?? []) {
        // Prefer a CVSS vector from any source; fall back to database_severity-free informational.
        const cvss = v.severity?.find((s) => s.type === "CVSS_V3")?.score
          ?? v.severity?.find((s) => s.type === "CVSS_V4")?.score
          ?? null;
        const score = cvss ? cvssBaseScore(cvss) : null;
        const fixed = v.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)?.fixed ?? null;
        out.push({
          cve: v.id ?? null,
          severity: score !== null ? cvssToSeverity(score) : "medium",
          cvss_score: score,
          cvss_vector: cvss,
          fixed_version: fixed ?? null,
          references: (v.references ?? []).map((r) => r.url ?? "").filter(Boolean).slice(0, 5),
        });
      }
      return out;
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  }
}

// ---------------------------------------------------------------------------
// CVSS 3.1 base score (spec arithmetic, no external deps)
// ---------------------------------------------------------------------------

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, U: 0.62, H_H: 0.5, H_U: 0.27, L_H: 0.68, L_U: 0.62 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/**
 * CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → base score.
 * Returns null for malformed vectors.
 */
export function cvssBaseScore(vector: string): number | null {
  const m = vector.match(/^CVSS:3\.[01]\/(.+)$/);
  if (!m) return null;
  const parts: Record<string, string> = {};
  for (const seg of m[1]!.split("/")) {
    const [k, v] = seg.split(":");
    if (!k || !v) return null;
    parts[k] = v;
  }
  const av = WEIGHTS.AV[parts["AV"] as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[parts["AC"] as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[parts["UI"] as keyof typeof WEIGHTS.UI];
  const scopeChanged = parts["S"] === "C";
  const prKey = parts["PR"];
  if (av === undefined || ac === undefined || ui === undefined || !prKey) return null;
  let pr: number;
  if (prKey === "N") pr = 0.85;
  else if (prKey === "L") pr = scopeChanged ? 0.68 : 0.62;
  else if (prKey === "H") pr = scopeChanged ? 0.5 : 0.27;
  else return null;

  const c = WEIGHTS.CIA[parts["C"] as keyof typeof WEIGHTS.CIA];
  const i = WEIGHTS.CIA[parts["I"] as keyof typeof WEIGHTS.CIA];
  const a = WEIGHTS.CIA[parts["A"] as keyof typeof WEIGHTS.CIA];
  if (c === undefined || i === undefined || a === undefined) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact: number;
  if (!scopeChanged) {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }
  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0;
  let score: number;
  if (!scopeChanged) score = Math.min(impact + exploitability, 10);
  else score = Math.min(1.08 * (impact + exploitability), 10);
  return roundUp1(score);
}

/** CVSS "Roundup" — smallest number with one decimal ≥ value. */
function roundUp1(value: number): number {
  const intInput = Math.round(value * 100000);
  switch (intInput % 10000) {
    case 0: return intInput / 100000;
    default: return (Math.floor(intInput / 10000) + 1) / 10;
  }
}

export function cvssToSeverity(score: number): CveLookup["severity"] {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "informational";
}

async function readBounded(resp: Response, max: number): Promise<string> {
  const reader = resp.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (total + value.byteLength > max) { chunks.push(value.subarray(0, max - total)); break; }
      chunks.push(value);
      total += value.byteLength;
    }
  }
  let out = "";
  for (const c of chunks) out += new TextDecoder().decode(c);
  return out;
}
