// src/providers/dns/doh.ts
// DNS-over-HTTPS adapter. Resolves A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, HTTPS.

import type { ProviderContext, ProviderResult, ReconProvider, ProviderAsset } from "../types.js";
import { LIMITS } from "../../constants.js";

const DOH_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
] as const;

const RECORD_TYPE_NUM: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257, HTTPS: 65,
};

export interface DnsAnswer {
  name: string;
  type: number;
  TTL?: number;
  data: string;
}

export interface DnsResult {
  records: { type: string; name: string; value: string; ttl: number | null }[];
  answers: DnsAnswer[];
}

export class DohProvider implements ReconProvider {
  readonly name = "doh";
  readonly kind = "dns" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    const records = await this.resolveAll(host, ctx);
    const assets: ProviderAsset[] = [];
    const seenIps = new Set<string>();
    for (const r of records) {
      if (r.type === "A" || r.type === "AAAA") {
        if (seenIps.has(r.value)) continue;
        seenIps.add(r.value);
        assets.push({
          type: "ip",
          value: r.value,
          normalized: r.value,
          source: this.name,
          confidence: 1.0,
          metadata: { hostname: r.name },
        });
      }
    }
    return {
      provider: this.name,
      assets,
      fetchedAt: new Date().toISOString(),
      cacheHit: false,
      metadata: records as unknown as Record<string, unknown>,
    } as ProviderResult;
  }

  async resolveAll(host: string, ctx: ProviderContext): Promise<DnsResult["records"]> {
    const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "HTTPS"];
    const out: DnsResult["records"] = [];
    await Promise.all(
      types.map(async (type) => {
        const r = await this.resolveOne(host, type, ctx);
        for (const a of r) out.push({ type, name: host, value: a.data, ttl: a.TTL ?? null });
      }),
    );
    return out;
  }

  async resolveOne(host: string, type: string, ctx: ProviderContext): Promise<DnsAnswer[]> {
    const endpoint = DOH_PROVIDERS[0]!;
    const url = `${endpoint}?name=${encodeURIComponent(host)}&type=${type}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(ctx.timeoutMs, LIMITS.MAX_REQUEST_TIMEOUT_MS));
    try {
      const resp = await fetch(url, {
        headers: { accept: "application/dns-json", "user-agent": ctx.userAgent },
        signal: controller.signal,
      });
      if (!resp.ok) return [];
      const json = (await resp.json()) as { Answer?: DnsAnswer[]; Status?: number };
      // Status 0 = NOERROR; 3 = NXDOMAIN
      if (json.Status !== undefined && json.Status !== 0 && json.Status !== 3) return [];
      return json.Answer ?? [];
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  }
}
