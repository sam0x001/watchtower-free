// src/utils/domain.ts
// Domain normalization & matching — used heavily by the scope engine.

import { punycodeEncode, punycodeDecode } from "./punycode.js";

export function normalizeDomain(input: string): string | null {
  if (!input || typeof input !== "string") return null;
  let v = input.trim().toLowerCase();
  if (!v) return null;
  // Strip wildcard
  if (v.startsWith("*.")) v = v.slice(2);
  // Strip scheme
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  // Strip path
  v = v.split("/")[0]!;
  // Strip port
  if (v.includes(":")) v = v.split(":")[0]!;
  if (!v) return null;

  // IDN → punycode
  try {
    if (/[^\x00-\x7F]/.test(v)) {
      const parts = v.split(".").map((p) => (/^\s*$/.test(p) ? p : punycodeEncode(p)));
      v = parts.join(".");
    }
  } catch {
    return null;
  }
  // Validate
  if (!/^[a-z0-9.-]+$/.test(v)) return null;
  if (v.startsWith("-") || v.endsWith("-")) return null;
  if (v.startsWith(".") || v.endsWith(".")) return null;
  if (v.includes("..")) return null;
  if (v.length > 253) return null;
  return v;
}

export function isSubdomainOf(child: string, parent: string): boolean {
  const c = normalizeDomain(child);
  const p = normalizeDomain(parent);
  if (!c || !p) return false;
  if (c === p) return true;
  return c.endsWith("." + p);
}

export function parentDomain(domain: string): string | null {
  const d = normalizeDomain(domain);
  if (!d) return null;
  const parts = d.split(".");
  if (parts.length < 3) return d;
  return parts.slice(-2).join(".");
}

export function isWildcard(input: string): boolean {
  const v = input.trim().toLowerCase();
  return v.startsWith("*.") || v === "*";
}

/** Returns true if `host` matches an entry like `example.com` or `*.example.com`. */
export function hostMatchesPattern(host: string, pattern: string): boolean {
  const h = normalizeDomain(host);
  if (!h) return false;
  const p = pattern.trim().toLowerCase();
  if (p === "*") return true;
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h.endsWith("." + base) || h === base;
  }
  return h === p;
}

export function rootDomain(host: string): string | null {
  return parentDomain(host);
}
