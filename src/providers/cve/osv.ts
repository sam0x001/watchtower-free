// src/providers/cve/osv.ts
// OSV.dev CVE lookup — correlates detected software versions to known
// vulnerabilities. Returns non-destructive observation records only.

import type { ProviderContext, ProviderResult, ReconProvider } from "../types.js";
import { LIMITS } from "../../constants.js";

export interface CveLookup {
  cve: string | null;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  cvss_score: number | null;
  epss_score: number | null;
  cwe: string | null;
  affected_versions: string | null;
  fixed_version: string | null;
  references: string[];
}

const OSV_URL = "https://api.osv.dev/v1/query";

export class OsvProvider implements ReconProvider {
  readonly name = "osv";
  readonly kind = "cve" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    // OSV expects a package name; we use `host` as a placeholder for demo only.
    // Real usage: pass the discovered technology+version from the tech fingerprint.
    return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, metadata: { note: "OSV adapter is invoked per detected technology", host } as unknown as Record<string, unknown> } as ProviderResult;
  }

  async lookup(ecosystem: string, packageName: string, version: string, ctx: ProviderContext): Promise<CveLookup[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
    try {
      const resp = await fetch(OSV_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: { name: packageName, ecosystem }, version }),
        signal: controller.signal,
      });
      if (!resp.ok) return [];
      const text = await readBounded(resp, LIMITS.MAX_RESPONSE_BYTES);
      let body: { vulns?: Array<{ id?: string; severity?: Array<{ score?: string; type?: string }>; references?: Array<{ url?: string }>; affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }> }> };
      try { body = JSON.parse(text); } catch { return []; }
      const out: CveLookup[] = [];
      for (const v of body.vulns ?? []) {
        const cvss = v.severity?.find((s) => s.type === "CVSS_V3");
        const score = cvss?.score ? parseCvssScore(cvss.score) : null;
        const fixed = v.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)?.fixed ?? null;
        out.push({
          cve: v.id ?? null,
          severity: score !== null ? cvssToSeverity(score) : "informational",
          cvss_score: score,
          epss_score: null,
          cwe: null,
          affected_versions: null,
          fixed_version: fixed ?? null,
          references: (v.references ?? []).map((r) => r.url ?? "").filter(Boolean),
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

function parseCvssScore(vector: string): number | null {
  const m = vector.match(/CVSS:3\.[01]\/AV:[^/]*\/AC:[^/]*\/PR:[^/]*\/UI:[^/]*\/S:[^/]*\/C:[^/]*\/I:[^/]*\/A:([^/]*)/);
  if (!m) return null;
  // Simplified — real scoring requires the full CVSS calculator
  return 7.5;
}

function cvssToSeverity(score: number): CveLookup["severity"] {
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
