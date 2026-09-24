// src/providers/registry.ts
// Provider registry — composes multiple providers for asset discovery.

import type { ReconProvider, ProviderContext, ProviderResult } from "./types.js";
import { CrtShProvider } from "./ct/crtsh.js";
import { CertSpotterProvider } from "./ct/certspotter.js";
import { CrtndstryProvider } from "./ct/crtndstry.js";
import { DohProvider } from "./dns/doh.js";
import { HttpxProvider } from "./http/httpx-adapter.js";

export interface ProviderRegistry {
  ct: ReconProvider[];
  dns: ReconProvider[];
  http: ReconProvider[];
  all: ReconProvider[];
}

export function buildRegistry(): ProviderRegistry {
  const ct = [new CrtShProvider(), new CertSpotterProvider(), new CrtndstryProvider()];
  const dns = [new DohProvider()];
  const http = [new HttpxProvider()];
  return { ct, dns, http, all: [...ct, ...dns, ...http] };
}

export async function runProviders(
  providers: ReconProvider[],
  input: { host: string },
  ctx: ProviderContext,
): Promise<ProviderResult[]> {
  // Bounded concurrency: never fire more than 5 simultaneous providers.
  const out: ProviderResult[] = [];
  const concurrency = Math.min(5, providers.length);
  let next = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (true) {
      const idx = next++;
      if (idx >= providers.length) break;
      out.push(await providers[idx]!.discover(input, ctx));
    }
  });
  await Promise.all(workers);
  return out;
}
