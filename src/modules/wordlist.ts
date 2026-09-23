// src/modules/wordlist.ts
// Authorization-gated wordlist module. Disabled by default.
// Validates every entry, prevents path traversal/SSRF, enforces per-target
// rate limits, stops on 429/5xx/overload.

import type { Env } from "../env.js";
import type { CompiledScope } from "../security/scope.js";
import { checkUrlInScope } from "../security/scope.js";
import { safeFetch } from "../security/ssrf.js";
import { joinUrl } from "../utils/url.js";
import { LIMITS } from "../constants.js";
import { sha256 } from "../crypto/hash.js";
import { randomId } from "../crypto/hash.js";

export interface WordlistEntry {
  value: string;
  category: string;
}

export interface WordlistProfile {
  name: string;
  categories: string[];
  maxRequests: number;
  maxConcurrency: number;
  delayMs: number;
  jitterMs: number;
  timeoutMs: number;
  maxResponseBytes: number;
  allowedStatusCodes: number[] | "all";
  allowedContentTypes: string[] | "all";
  redirectPolicy: "in_scope" | "none";
  authenticationPolicy: "none";
  notificationPolicy: "immediate" | "batch";
  retentionDays: number;
  requiresHumanApproval: boolean;
  schedule: string;
  stopConditions: string[];
}

export const WORDLIST_PROFILES: Record<string, WordlistProfile> = {
  "passive-only": {
    name: "passive-only",
    categories: [],
    maxRequests: 0,
    maxConcurrency: 1,
    delayMs: 1000,
    jitterMs: 500,
    timeoutMs: 10000,
    maxResponseBytes: 1 * 1024 * 1024,
    allowedStatusCodes: [],
    allowedContentTypes: [],
    redirectPolicy: "none",
    authenticationPolicy: "none",
    notificationPolicy: "immediate",
    retentionDays: 90,
    requiresHumanApproval: false,
    schedule: "daily",
    stopConditions: ["429", "5xx_x3", "timeout_x3"],
  },
  "low-impact-web-content": {
    name: "low-impact-web-content",
    categories: ["directories", "files", "backup", "config", "documentation", "static"],
    maxRequests: 200,
    maxConcurrency: 2,
    delayMs: 500,
    jitterMs: 250,
    timeoutMs: 10000,
    maxResponseBytes: 1 * 1024 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: "all",
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 90,
    requiresHumanApproval: true,
    schedule: "daily",
    stopConditions: ["429", "5xx_x3", "timeout_x3", "403_x5"],
  },
  "low-impact-api-discovery": {
    name: "low-impact-api-discovery",
    categories: ["api", "api_version", "graphql", "openapi"],
    maxRequests: 100,
    maxConcurrency: 2,
    delayMs: 800,
    jitterMs: 400,
    timeoutMs: 10000,
    maxResponseBytes: 512 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: "all",
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 90,
    requiresHumanApproval: true,
    schedule: "daily",
    stopConditions: ["429", "5xx_x3", "timeout_x3"],
  },
  "javascript-monitoring": {
    name: "javascript-monitoring",
    categories: ["javascript", "sourcemap"],
    maxRequests: 100,
    maxConcurrency: 2,
    delayMs: 400,
    jitterMs: 200,
    timeoutMs: 10000,
    maxResponseBytes: 2 * 1024 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: ["application/javascript", "text/javascript"],
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 90,
    requiresHumanApproval: false,
    schedule: "hourly",
    stopConditions: ["429", "5xx_x3", "timeout_x3"],
  },
  "subdomain-monitoring": {
    name: "subdomain-monitoring",
    categories: ["subdomain"],
    maxRequests: 0, // DNS-only
    maxConcurrency: 1,
    delayMs: 1000,
    jitterMs: 500,
    timeoutMs: 5000,
    maxResponseBytes: 64 * 1024,
    allowedStatusCodes: [],
    allowedContentTypes: [],
    redirectPolicy: "none",
    authenticationPolicy: "none",
    notificationPolicy: "immediate",
    retentionDays: 90,
    requiresHumanApproval: false,
    schedule: "daily",
    stopConditions: [],
  },
  "technology-specific": {
    name: "technology-specific",
    categories: ["tech_specific"],
    maxRequests: 100,
    maxConcurrency: 2,
    delayMs: 600,
    jitterMs: 300,
    timeoutMs: 10000,
    maxResponseBytes: 512 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: "all",
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 90,
    requiresHumanApproval: true,
    schedule: "weekly",
    stopConditions: ["429", "5xx_x3"],
  },
  "custom-authorized": {
    name: "custom-authorized",
    categories: ["custom"],
    maxRequests: 50,
    maxConcurrency: 1,
    delayMs: 1000,
    jitterMs: 500,
    timeoutMs: 10000,
    maxResponseBytes: 512 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: "all",
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 30,
    requiresHumanApproval: true,
    schedule: "weekly",
    stopConditions: ["429", "5xx_x3"],
  },
  "full-approved-monitoring": {
    name: "full-approved-monitoring",
    categories: ["directories", "files", "backup", "config", "api", "api_version", "graphql", "documentation", "static", "javascript", "sourcemap", "subdomain", "tech_specific", "custom"],
    maxRequests: 500,
    maxConcurrency: 2,
    delayMs: 800,
    jitterMs: 400,
    timeoutMs: 10000,
    maxResponseBytes: 2 * 1024 * 1024,
    allowedStatusCodes: "all",
    allowedContentTypes: "all",
    redirectPolicy: "in_scope",
    authenticationPolicy: "none",
    notificationPolicy: "batch",
    retentionDays: 90,
    requiresHumanApproval: true,
    schedule: "weekly",
    stopConditions: ["429", "5xx_x3", "timeout_x3"],
  },
};

export interface FuzzResult {
  url: string;
  status: number;
  contentType: string | null;
  contentLength: number;
  title: string | null;
  bodyHash: string;
  redirectChain: string[];
  elapsedMs: number;
  isNew: boolean;
  classification: string;
}

export async function runWordlist(
  env: Env,
  baseUrl: string,
  scope: CompiledScope,
  wordlist: string[],
  profile: WordlistProfile,
): Promise<FuzzResult[]> {
  const results: FuzzResult[] = [];
  let consecutiveErrors = 0;
  let consecutiveTimeouts = 0;
  let requestsMade = 0;

  for (const entry of wordlist) {
    if (requestsMade >= profile.maxRequests) break;
    if (consecutiveErrors >= 5) break;
    if (consecutiveTimeouts >= 3) break;

    // Sanitize entry
    const sanitized = sanitizeWordlistEntry(entry);
    if (!sanitized) continue;

    const url = joinUrl(baseUrl, sanitized);
    if (!url) continue;
    const scopeCheck = checkUrlInScope(scope, url);
    if (!scopeCheck.allowed) continue;

    try {
      const r = await safeFetch(env, url, {
        scope,
        method: "GET",
        timeoutMs: profile.timeoutMs,
        maxBytes: profile.maxResponseBytes,
        userAgent: env.USER_AGENT,
        followRedirects: profile.redirectPolicy === "in_scope",
      });
      requestsMade++;
      if (r.status === 429) { break; }
      if (r.status >= 500) { consecutiveErrors++; continue; }
      consecutiveErrors = 0;
      consecutiveTimeouts = 0;

      const text = new TextDecoder().decode(r.body);
      const bodyHash = await sha256(text);
      const title = (text.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)?.[1] ?? "").trim() || null;
      results.push({
        url,
        status: r.status,
        contentType: r.headers["content-type"] ?? null,
        contentLength: r.body.byteLength,
        title,
        bodyHash,
        redirectChain: r.finalUrl !== url ? [r.finalUrl] : [],
        elapsedMs: r.elapsedMs,
        isNew: true, // determined by caller against baseline
        classification: classifyResponse(r.status, r.headers["content-type"] ?? "", title),
      });

      // Delay + jitter
      const wait = profile.delayMs + Math.floor(Math.random() * profile.jitterMs);
      await new Promise((resolve) => setTimeout(resolve, wait));
    } catch (err) {
      if (String(err).includes("timeout")) consecutiveTimeouts++;
      consecutiveErrors++;
    }
  }

  return results;
}

export function sanitizeWordlistEntry(entry: string): string | null {
  let v = entry.trim();
  if (!v) return null;
  if (v.startsWith("#")) return null;
  if (v.length > LIMITS.MAX_WORDLIST_ENTRY_LENGTH) return null;
  // Path traversal
  if (v.includes("..")) return null;
  if (v.includes("\0")) return null;
  // NUL or control chars
  if (/[\x00-\x1f]/.test(v)) return null;
  // URL-encode-safe: letters, digits, _ - / . ~ : @ ! $ & ' ( ) * + , ; =
  if (!/^[A-Za-z0-9_\-\/.~:@!$&'()*+,;=%]+$/.test(v)) return null;
  return v;
}

function classifyResponse(status: number, contentType: string, title: string | null): string {
  if (status === 200) {
    if (/application\/json/.test(contentType)) return "new_api_route";
    if (/text\/html/.test(contentType) && title && /admin|login|dashboard/i.test(title)) return "new_admin_panel";
    if (/\/\.env|\.config|\.bak|\.old|\.sql|\.zip|\.tar/.test("")) return "new_backup_file";
    return "new_endpoint";
  }
  if (status === 401 || status === 403) return "authentication_behavior_changed";
  if (status === 404) return "false_positive";
  if (status >= 300 && status < 400) return "redirect_changed";
  return "requires_manual_review";
}

export async function loadWordlist(db: D1Database, wordlistId: string): Promise<string[]> {
  const r = await db.prepare(`SELECT r2_key FROM wordlists WHERE id = ?`).bind(wordlistId).first<{ r2_key: string }>();
  if (!r) return [];
  return [] as string[];
}

export async function storeWordlist(
  db: D1Database,
  orgId: string | null,
  name: string,
  category: string,
  source: string,
  entries: string[],
): Promise<{ id: string; accepted: number; rejected: number; checksum: string }> {
  const accepted: string[] = [];
  let rejected = 0;
  const seen = new Set<string>();
  for (const raw of entries) {
    const v = sanitizeWordlistEntry(raw);
    if (!v) { rejected++; continue; }
    if (seen.has(v)) continue;
    seen.add(v);
    accepted.push(v);
    if (accepted.length >= LIMITS.MAX_WORDLIST_ENTRIES) break;
  }
  const checksum = await sha256(accepted.join("\n"));
  const id = randomId("wl", 12);
  await db
    .prepare(`INSERT INTO wordlists (id, organization_id, name, version, category, source, r2_key, entry_count, content_hash, created_at, updated_at) VALUES (?, ?, ?, '1.0.0', ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, orgId, name, category, source, `wordlist/${id}.txt`, accepted.length, checksum, new Date().toISOString(), new Date().toISOString())
    .run();
  return { id, accepted: accepted.length, rejected, checksum };
}
