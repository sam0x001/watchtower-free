// src/providers/ct/crtndstry.ts
// crtndstry adapter — falls back to a JSON endpoint; never relies on HTML scraping.
// If crtndstry is unreachable, we return no assets rather than scraping HTML.

import type { ProviderContext, ProviderResult, ReconProvider, ProviderAsset } from "../types.js";
import { LIMITS } from "../../constants.js";
import { normalizeDomain } from "../../utils/domain.js";
import { sha256 } from "../../crypto/hash.js";

interface CrtndstryResponse {
  subdomains?: string[];
}

const URL = (host: string) => `https://crtndstry.io/ct/search?q=${encodeURIComponent(host)}`;

export class CrtndstryProvider implements ReconProvider {
  readonly name = "crtndstry";
  readonly kind = "certificate_transparency" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    const url = URL(host);
    const cacheKey = `crtndstry:${await sha256(url)}`;
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
        return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, error: "rate limited" };
      }
      if (!resp.ok) {
        return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, error: `HTTP ${resp.status}` };
      }
      const text = await readBounded(resp, Math.min(ctx.maxResponseBytes, LIMITS.MAX_CERT_PROVIDER_RESPONSE_BYTES));
      let body: CrtndstryResponse;
      try { body = JSON.parse(text) as CrtndstryResponse; } catch {
        return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, error: "invalid JSON" };
      }
      const seen = new Set<string>();
      const assets: ProviderAsset[] = [];
      for (const raw of body.subdomains ?? []) {
        const norm = normalizeDomain(raw);
        if (!norm || seen.has(norm)) continue;
        seen.add(norm);
        assets.push({
          type: "certificate",
          value: norm,
          normalized: norm,
          source: this.name,
          confidence: 0.9,
        });
      }
      const result: ProviderResult = { provider: this.name, assets, fetchedAt: new Date().toISOString(), cacheHit: false };
      await ctx.cache?.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 }).catch(() => undefined);
      return result;
    } catch (err) {
      return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, error: String(err) };
    } finally {
      clearTimeout(timer);
    }
  }
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
      if (total + value.byteLength > max) {
        chunks.push(value.subarray(0, max - total));
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  }
  let out = "";
  for (const c of chunks) out += new TextDecoder().decode(c);
  return out;
}
