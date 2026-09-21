// src/providers/http/httpx-adapter.ts
// Safe HTTP discovery adapter — uses the Worker's own fetch (already SSRF-guarded
// upstream) to probe a host for HTTP metadata. Does NOT execute JavaScript, does
// NOT submit forms, does NOT follow cross-scope redirects.

import type { ProviderContext, ProviderResult, ReconProvider, ProviderAsset } from "../types.js";
import { LIMITS } from "../../constants.js";
import { validateRedirect } from "../../security/redirect.js";
import type { CompiledScope } from "../../security/scope.js";
import { checkUrlInScope } from "../../security/scope.js";

export interface HttpProbeResult {
  url: string;
  finalUrl: string;
  status: number;
  title: string | null;
  server: string | null;
  contentType: string | null;
  contentLength: number;
  redirects: string[];
  securityHeaders: Record<string, string | null>;
  technologies: string[];
  bodyHash: string;
}

export class HttpxProvider implements ReconProvider {
  readonly name = "httpx-worker";
  readonly kind = "http" as const;

  async discover({ host }: { host: string }, ctx: ProviderContext): Promise<ProviderResult> {
    // Probe https:// then http://
    const probe = await this.probeUrl(`https://${host}/`, host, ctx);
    if (probe) return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, metadata: probe as unknown as Record<string, unknown> } as ProviderResult;
    const probe2 = await this.probeUrl(`http://${host}/`, host, ctx);
    return { provider: this.name, assets: [], fetchedAt: new Date().toISOString(), cacheHit: false, metadata: probe2 as unknown as Record<string, unknown> } as ProviderResult;
  }

  async probeUrl(
    url: string,
    _host: string,
    ctx: ProviderContext,
    scope?: CompiledScope,
    maxRedirects = 3,
  ): Promise<HttpProbeResult | null> {
    if (scope) {
      const scopeCheck = checkUrlInScope(scope, url);
      if (!scopeCheck.allowed) return null;
    }
    let current = url;
    const redirects: string[] = [];
    for (let i = 0; i < maxRedirects + 1; i++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
      try {
        const resp = await fetch(current, {
          method: "GET",
          headers: { "user-agent": ctx.userAgent },
          redirect: "manual",
          signal: controller.signal,
        });
        clearTimeout(timer);
        if ([301, 302, 303, 307, 308].includes(resp.status)) {
          const loc = resp.headers.get("location") ?? "";
          if (!loc) break;
          if (scope) {
            const r = validateRedirect(current, loc, scope);
            if (!r.allowed || !r.finalUrl) break;
            current = r.finalUrl;
          } else {
            current = new URL(loc, current).href;
          }
          redirects.push(current);
          continue;
        }
        const body = await readBounded(resp, LIMITS.MAX_RESPONSE_BYTES);
        const bodyHash = await hashSha256(body);
        const title = extractTitle(body);
        const server = resp.headers.get("server");
        const contentType = resp.headers.get("content-type");
        const securityHeaders = {
          "strict-transport-security": resp.headers.get("strict-transport-security"),
          "content-security-policy": resp.headers.get("content-security-policy"),
          "x-frame-options": resp.headers.get("x-frame-options"),
          "x-content-type-options": resp.headers.get("x-content-type-options"),
          "referrer-policy": resp.headers.get("referrer-policy"),
          "permissions-policy": resp.headers.get("permissions-policy"),
        };
        const technologies = fingerprintTechnologies(resp.headers, body);
        return {
          url,
          finalUrl: current,
          status: resp.status,
          title,
          server,
          contentType,
          contentLength: body.byteLength,
          redirects,
          securityHeaders,
          technologies,
          bodyHash,
        };
      } catch {
        clearTimeout(timer);
        return null;
      }
    }
    return null;
  }
}

async function readBounded(resp: Response, max: number): Promise<Uint8Array> {
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
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}

function extractTitle(body: Uint8Array): string | null {
  const text = new TextDecoder().decode(body.subarray(0, Math.min(body.byteLength, 1_000_000)));
  const m = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m || !m[1]) return null;
  return m[1].trim().slice(0, 200);
}

function fingerprintTechnologies(headers: Headers, body: Uint8Array): string[] {
  const out: string[] = [];
  const server = (headers.get("server") ?? "").toLowerCase();
  const powered = (headers.get("x-powered-by") ?? "").toLowerCase();
  if (server.includes("nginx")) out.push("nginx");
  if (server.includes("apache")) out.push("apache");
  if (server.includes("cloudflare")) out.push("cloudflare");
  if (server.includes("gunicorn")) out.push("gunicorn");
  if (powered.includes("express")) out.push("express");
  if (powered.includes("php")) out.push("php");
  if (powered.includes("asp.net")) out.push("asp.net");
  const text = new TextDecoder().decode(body.subarray(0, Math.min(body.byteLength, 200_000)));
  if (/window\.__NUXT__/.test(text)) out.push("nuxt");
  if (/window\.__NEXT_DATA__/.test(text)) out.push("next.js");
  if (/window\.__INITIAL_STATE__/.test(text) && /vue/.test(text.toLowerCase())) out.push("vue");
  if (/react/i.test(text) && /data-reactroot/.test(text)) out.push("react");
  if (/wp-content\//.test(text)) out.push("wordpress");
  if (/cdn\.jsdelivr\.net/.test(text)) out.push("jsdelivr");
  return Array.from(new Set(out));
}

async function hashSha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i]!.toString(16).padStart(2, "0");
  return hex;
}
