// src/modules/dns-bruteforce.ts
// Wordlist-based subdomain discovery via DNS-over-HTTPS, chunked to fit the
// Cloudflare Workers free tier (one chunk of the wordlist per scan tick).
//
// Includes a wildcard-DNS guard: before bruteforcing, a random label is
// resolved once per target. If gibberish subdomains resolve, the domain is
// wildcarded and any bruteforce hit whose IPs are all wildcard IPs is
// discarded — otherwise every name in the list would falsely "resolve".

import type { Env } from "../env.js";
import type { CompiledScope } from "../security/scope.js";
import { checkHostInScope } from "../security/scope.js";
import { DohProvider } from "../providers/dns/doh.js";
import type { ProviderContext } from "../providers/types.js";
import { upsertAsset } from "../db/queries/assets.js";
import { buildAlert, type Alert } from "./alerts.js";
import subdomainsTxt from "../../fuzz-wordlists/subdomains.txt";

export interface BruteforceResult {
  alerts: Alert[];
  /** True when the whole wordlist has been processed for this cycle. */
  done: boolean;
  resolved: number;
  skippedWildcard: number;
  cursor: number;
  total: number;
}

const CURSOR_PREFIX = "bf:";
const WILDCARD_PREFIX = "wc:";
const WILDCARD_TTL_SECONDS = 7 * 24 * 3600;

/** The subdomain wordlist, sanitized once per isolate. */
let cachedEntries: string[] | null = null;
export function subdomainWordlist(): string[] {
  if (!cachedEntries) {
    cachedEntries = subdomainsTxt
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#") && l.length <= 100)
      .map((l) => (l.startsWith("*.") ? l.slice(2) : l))
      .filter((l) => /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(l));
  }
  return cachedEntries;
}

/**
 * Detects wildcard DNS for `domain`. Returns the set of IPs that gibberish
 * subdomains resolve to (empty set = no wildcard). Cached in KV for a week.
 */
export async function getWildcardIps(
  env: Env,
  targetId: string,
  domain: string,
  ctx: ProviderContext,
): Promise<string[]> {
  const cacheKey = `${WILDCARD_PREFIX}${targetId}`;
  try {
    const cached = await env.CACHE.get(cacheKey);
    if (cached) return JSON.parse(cached) as string[];
  } catch { /* fall through to live check */ }

  const nonce = `wt-${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}`;
  const doh = new DohProvider();
  const answers = await doh.resolveOne(`${nonce}.${domain}`, "A", ctx);
  const ips = answers.filter((a) => a.type === 1).map((a) => a.data);

  try {
    await env.CACHE.put(cacheKey, JSON.stringify(ips), { expirationTtl: WILDCARD_TTL_SECONDS });
  } catch { /* cache write failures are non-fatal */ }
  return ips;
}

/**
 * Resolve the next chunk of the subdomain wordlist for a target, upsert any
 * newly found subdomains, and advance the per-target cursor in KV.
 */
export async function runBruteforceChunk(
  env: Env,
  targetId: string,
  domain: string,
  scope: CompiledScope,
  wildcardIps: string[],
  ctx: ProviderContext,
  chunkSize: number,
  concurrency = 16,
): Promise<BruteforceResult> {
  const entries = subdomainWordlist();
  const cursorRaw = await env.CACHE.get(`${CURSOR_PREFIX}${targetId}`);
  let cursor = cursorRaw ? Number(cursorRaw) : 0;
  if (!Number.isFinite(cursor) || cursor < 0 || cursor >= entries.length) cursor = 0;

  const chunk = entries.slice(cursor, cursor + chunkSize);
  const doh = new DohProvider();
  const alerts: Alert[] = [];
  let resolved = 0;
  let skippedWildcard = 0;

  // Bounded-concurrency resolution (BRUTEFORCE_CONCURRENCY DoH lookups in flight).
  const lanes = Math.max(1, Math.min(concurrency, chunk.length));
  let next = 0;
  const workers = Array.from({ length: lanes }, async () => {
    while (true) {
      const idx = next++;
      if (idx >= chunk.length) break;
      const label = chunk[idx]!;
      // Some lists contain full hostnames — accept both forms.
      const host = label.endsWith(`.${domain}`) ? label : `${label}.${domain}`;
      if (!checkHostInScope(scope, host).allowed) continue;

      const answers = await doh.resolveOne(host, "A", ctx);
      const ips = answers.filter((a) => a.type === 1).map((a) => a.data);
      if (ips.length === 0) continue;
      resolved++;

      // Wildcard guard: a hit that only resolves to wildcard IPs is noise.
      if (wildcardIps.length > 0 && ips.every((ip) => wildcardIps.includes(ip))) {
        skippedWildcard++;
        continue;
      }

      const res = await upsertAsset(env.DB, targetId, "subdomain", host, host, "in_scope", {
        source: "dns-bruteforce",
        ips,
      });
      if (res.created) {
        alerts.push(buildAlert("new_subdomain", targetId, {
          asset_id: res.id,
          asset_value: host,
          title: `New subdomain discovered: ${host}`,
          summary:
            `A new in-scope subdomain was found via wordlist bruteforce.\n\n` +
            `Hostname: ${host}\nIP: ${ips.join(", ")}\nSource: dns-bruteforce`,
          metadata: { source: "dns-bruteforce", ips },
        }));
      }
    }
  });
  await Promise.all(workers);

  const newCursor = cursor + chunk.length;
  const done = newCursor >= entries.length;
  try {
    // Cycle back to 0 when the list is exhausted so hosts are re-checked
    // periodically; dedup ensures nothing re-alerts.
    await env.CACHE.put(`${CURSOR_PREFIX}${targetId}`, String(done ? 0 : newCursor));
  } catch { /* non-fatal */ }

  return { alerts, done, resolved, skippedWildcard, cursor: newCursor, total: entries.length };
}
