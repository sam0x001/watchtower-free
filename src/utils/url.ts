// src/utils/url.ts
// Safe URL canonicalization with strict scope enforcement.

const SAFE_SCHEMES = new Set(["http:", "https:"]);

export interface ParsedUrl {
  href: string;
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  search: string;
  hash: string;
  origin: string;
}

export function parseUrl(input: string): ParsedUrl | null {
  let v: string;
  try {
    v = input.trim();
    if (!v) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
      // bare host? add https
      v = "https://" + v;
    }
    const u = new URL(v);
    if (!SAFE_SCHEMES.has(u.protocol.toLowerCase())) return null;
    if (!u.hostname) return null;
    return {
      href: u.href,
      scheme: u.protocol.toLowerCase(),
      host: u.hostname.toLowerCase(),
      port: u.port ? Number(u.port) : (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search,
      search: u.search,
      hash: u.hash,
      origin: u.origin,
    };
  } catch {
    return null;
  }
}

export function canonicalizeUrl(input: string): string | null {
  const p = parseUrl(input);
  if (!p) return null;
  // Drop fragment
  // Default port → omit
  const portSuffix =
    p.port === null || (p.scheme === "https:" && p.port === 443) ||
    (p.scheme === "http:" && p.port === 80)
      ? ""
      : `:${p.port}`;
  // Trailing slash semantics: keep "/" for root path
  let path = p.path || "/";
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  return `${p.scheme}//${p.host}${portSuffix}${path}`;
}

export function urlHost(input: string): string | null {
  const p = parseUrl(input);
  return p?.host ?? null;
}

export function joinUrl(base: string, relative: string): string | null {
  try {
    const u = new URL(relative, base);
    if (!SAFE_SCHEMES.has(u.protocol.toLowerCase())) return null;
    return u.href;
  } catch {
    return null;
  }
}

export function isSameOrigin(a: string, b: string): boolean {
  const pa = parseUrl(a);
  const pb = parseUrl(b);
  if (!pa || !pb) return false;
  return pa.origin === pb.origin;
}
