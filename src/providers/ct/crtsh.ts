// src/providers/ct/crtsh.ts
// crt.sh Certificate Transparency adapter.
//
// Memory-safe: streams the JSON response through a bounded parser. We never
// load more than `maxResponseBytes` into a single buffer.

import type { ProviderContext, ProviderResult, ReconProvider, ProviderAsset } from "../types.js";
import { LIMITS } from "../../constants.js";
import { normalizeDomain } from "../../utils/domain.js";
import { sha256 } from "../../crypto/hash.js";

interface CrtShEntry {
  issuer_ca_id?: number;
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  id?: number;
  entry_timestamp?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

const CRTSH_URL = (host: string) => `https://crt.sh/?q=${encodeURIComponent("%." + host)}&output=json`;

export class CrtShProvider implements ReconProvider {
  readonly name = "crt.sh";
  readonly kind = "certificate_transparency" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    const url = CRTSH_URL(host);
    const cacheKey = `crtsh:${await sha256(url)}`;
    const cached = await ctx.cache?.get(cacheKey, "json").catch(() => null);
    if (cached) return { ...cached as ProviderResult, cacheHit: true };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
    try {
      const resp = await fetch(url, {
        headers: {
          accept: "application/json",
          "user-agent": ctx.userAgent,
        },
        signal: controller.signal,
      });
      if (resp.status === 429 || resp.status === 502 || resp.status === 503) {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: `crt.sh returned ${resp.status}; treating as transient (NOT as asset removal)`,
        };
      }
      if (!resp.ok) {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: `crt.sh returned HTTP ${resp.status}`,
        };
      }

      // Bounded read: limit to maxResponseBytes
      const reader = resp.body?.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      const max = Math.min(ctx.maxResponseBytes, LIMITS.MAX_CERT_PROVIDER_RESPONSE_BYTES);
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
      const text = concatText(chunks);
      let entries: CrtShEntry[] = [];
      try {
        entries = JSON.parse(text) as CrtShEntry[];
      } catch {
        return {
          provider: this.name,
          assets: [],
          fetchedAt: new Date().toISOString(),
          cacheHit: false,
          error: truncated ? "response truncated; refusing to parse partial JSON" : "invalid JSON",
        };
      }

      // Bounded deduplication using a Set with a ceiling
      const seen = new Set<string>();
      const assets: ProviderAsset[] = [];
      const maxNames = 50_000;
      let count = 0;
      for (const e of entries) {
        const raw = e.name_value ?? e.common_name ?? "";
        if (!raw) continue;
        for (const line of raw.split("\n")) {
          if (count >= maxNames) break;
          const norm = normalizeDomain(line.trim());
          if (!norm) continue;
          if (seen.has(norm)) continue;
          seen.add(norm);
          assets.push({
            type: "certificate",
            value: norm,
            normalized: norm,
            source: this.name,
            confidence: 0.95,
            metadata: {
              issuer: e.issuer_name ?? null,
              serial: e.serial_number ?? null,
              not_before: e.not_before ?? null,
              not_after: e.not_after ?? null,
              crtsh_id: e.id ?? null,
            },
          });
          count++;
        }
      }

      const result: ProviderResult = {
        provider: this.name,
        assets,
        fetchedAt: new Date().toISOString(),
        cacheHit: false,
        error: truncated ? `truncated at ${max} bytes; partial result` : undefined,
      };
      await ctx.cache?.put(cacheKey, JSON.stringify(result), {
        expirationTtl: 300,
      }).catch(() => undefined);
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

function concatText(chunks: Uint8Array[]): string {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return new TextDecoder().decode(out);
}
