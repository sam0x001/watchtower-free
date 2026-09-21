// src/providers/ct/certspotter.ts
// Cert Spotter (SSLMate) adapter — bounded, scope-aware.

import type { ProviderContext, ProviderResult, ReconProvider, ProviderAsset } from "../types.js";
import { LIMITS } from "../../constants.js";
import { normalizeDomain } from "../../utils/domain.js";
import { sha256 } from "../../crypto/hash.js";

interface CertSpotterIssuance {
  id?: string;
  cert?: { issuer?: { name?: string }; serial_number?: string; not_before?: string; not_after?: string };
  dns_names?: string[];
}

const URL = (host: string) => `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=true&expand=dns_names&expand=cert`;

export class CertSpotterProvider implements ReconProvider {
  readonly name = "certspotter";
  readonly kind = "certificate_transparency" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    const url = URL(host);
    const cacheKey = `certspotter:${await sha256(url)}`;
    const cached = await ctx.cache?.get(cacheKey, "json").catch(() => null);
    if (cached) return { ...(cached as ProviderResult), cacheHit: true };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
    try {
      const resp = await fetch(url, {
        headers: { accept: "application/json", "user-agent": ctx.userAgent },
        signal: controller.signal,
      });
      if (resp.status === 429) {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: "certspotter rate limit; not treating as removal",
        };
      }
      if (!resp.ok) {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: `certspotter returned ${resp.status}`,
        };
      }
      const text = await readBounded(resp, Math.min(ctx.maxResponseBytes, LIMITS.MAX_CERT_PROVIDER_RESPONSE_BYTES));
      let issuances: CertSpotterIssuance[] = [];
      try { issuances = JSON.parse(text) as CertSpotterIssuance[]; } catch {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: "invalid JSON",
        };
      }
      const seen = new Set<string>();
      const assets: ProviderAsset[] = [];
      let count = 0;
      const max = 50_000;
      for (const iss of issuances) {
        for (const name of iss.dns_names ?? []) {
          if (count >= max) break;
          const norm = normalizeDomain(name);
          if (!norm) continue;
          if (seen.has(norm)) continue;
          seen.add(norm);
          assets.push({
            type: "certificate",
            value: norm,
            normalized: norm,
            source: this.name,
            confidence: 0.93,
            metadata: {
              issuance_id: iss.id ?? null,
              issuer: iss.cert?.issuer?.name ?? null,
              serial: iss.cert?.serial_number ?? null,
              not_before: iss.cert?.not_before ?? null,
              not_after: iss.cert?.not_after ?? null,
            },
          });
          count++;
        }
      }
      const result: ProviderResult = { provider: this.name, assets, fetchedAt: new Date().toISOString(), cacheHit: false };
      await ctx.cache?.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 }).catch(() => undefined);
      return result;
    } catch (err) {
      return {
        provider: this.name,
        assets: [],
        fetchedAt: new Date().toISOString(),
        cacheHit: false,
        error: String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

async function readBounded(resp: Response, max: number): Promise<string> {
  const reader = resp.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (total + value.byteLength > max) {
        chunks.push(value.subarray(0, max - total));
        truncated = true;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  }
  let out = "";
  for (const c of chunks) out += new TextDecoder().decode(c);
  return out + (truncated ? "" : "");
}
