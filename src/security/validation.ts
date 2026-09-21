// src/security/validation.ts
// Input validation primitives — Telegram command args, API payloads, webhook bodies.

import { normalizeDomain } from "../utils/domain.js";
import { parseIP, parseCIDR } from "../utils/ip.js";
import { parseUrl, canonicalizeUrl } from "../utils/url.js";
import type { ScopeType } from "../types.js";

export interface ValidationError {
  field: string;
  message: string;
}

export function validateTargetName(name: string): ValidationError | null {
  const v = name?.trim();
  if (!v) return { field: "name", message: "Target name is required" };
  if (v.length > 120) return { field: "name", message: "Target name must be ≤120 chars" };
  if (!/^[\w\-.\s]+$/.test(v)) {
    return { field: "name", message: "Target name may only contain letters, digits, spaces, _ . -" };
  }
  return null;
}

export function validateScopeValue(type: ScopeType, value: string): ValidationError | null {
  const v = value?.trim();
  if (!v) return { field: "value", message: "Scope value is required" };
  if (v.length > 1024) return { field: "value", message: "Scope value too long" };
  switch (type) {
    case "domain":
      if (!normalizeDomain(v)) return { field: "value", message: "Invalid domain" };
      return null;
    case "wildcard_domain":
      if (!/^(\*\.)?[\w\-.]+$/.test(v)) return { field: "value", message: "Invalid wildcard domain" };
      return null;
    case "ip":
      if (!parseIP(v)) return { field: "value", message: "Invalid IP address" };
      return null;
    case "cidr":
      if (!parseCIDR(v)) return { field: "value", message: "Invalid CIDR" };
      return null;
    case "url":
    case "api":
      if (!parseUrl(v)) return { field: "value", message: "Invalid URL" };
      return null;
    case "repository":
      if (!/^[\w\-.\/:@]+$/.test(v)) return { field: "value", message: "Invalid repository identifier" };
      return null;
    case "cloud_account":
      if (!/^[\w\-:]+$/.test(v)) return { field: "value", message: "Invalid cloud account identifier" };
      return null;
    case "mobile_app":
      if (!/^[\w.\-]+$/.test(v)) return { field: "value", message: "Invalid app identifier" };
      return null;
  }
  return null;
}

export function validateISODate(v: string): ValidationError | null {
  if (!v) return { field: "date", message: "Date is required" };
  const d = new Date(v);
  if (isNaN(d.getTime())) return { field: "date", message: "Invalid ISO date" };
  return null;
}

export function validateRateLimit(v: number | string): ValidationError | null {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 1 || n > 1000) {
    return { field: "rate_limit", message: "Rate limit must be between 1 and 1000 r/min" };
  }
  return null;
}

export function validatePath(v: string): ValidationError | null {
  if (!v.startsWith("/")) return { field: "path", message: "Path must start with /" };
  if (v.length > 2048) return { field: "path", message: "Path too long" };
  if (v.includes("..")) return { field: "path", message: "Path traversal not allowed" };
  if (v.includes("\0")) return { field: "path", message: "NUL byte in path" };
  return null;
}

export function validatePort(v: number): ValidationError | null {
  if (!Number.isInteger(v) || v < 1 || v > 65535) {
    return { field: "port", message: "Port must be 1..65535" };
  }
  return null;
}

export function validateTelegramId(v: string | number): ValidationError | null {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0 || n > 1e13) {
    return { field: "telegram_id", message: "Invalid Telegram ID" };
  }
  return null;
}

export function validateEmail(v: string): ValidationError | null {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { field: "email", message: "Invalid email" };
  return null;
}

export function sanitizeDisplayString(v: string, maxLen: number): string {
  // Strip control characters and zero-width characters that could be used
  // for spoofing or report injection.
  return v
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u2028\u2029\uFEFF]/g, "")
    .slice(0, maxLen);
}

export function validateUrlString(v: string): string | null {
  return canonicalizeUrl(v);
}
