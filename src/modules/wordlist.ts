// src/modules/wordlist.ts
// Sensitive-data / endpoint fuzzing with the bundled wordlists
// (fuzz-wordlists/api.txt, directories.txt, files.txt, fuzz.txt).
//
// Free-tier aware: processes a bounded number of requests per host per tick
// (FUZZ_REQUESTS_PER_TICK), throttled, stopping on 429/5xx streaks. Every
// entry is sanitized (no traversal, no control chars) and scope-checked
// (denylist exclusions honored) before any request is made.
//
// Findings (sensitive-looking responses: .env content, backups, admin panels,
// exposed configs) are persisted in `findings` and alerted once.

import type { Env } from "../env.js";
import type { CompiledScope } from "../security/scope.js";
import { checkUrlInScope } from "../security/scope.js";
import { safeFetch } from "../security/ssrf.js";
import { joinUrl } from "../utils/url.js";
import { LIMITS } from "../constants.js";
import { sha256 } from "../crypto/hash.js";
import apiTxt from "../../fuzz-wordlists/api.txt";
import directoriesTxt from "../../fuzz-wordlists/directories.txt";
import filesTxt from "../../fuzz-wordlists/files.txt";
import fuzzTxt from "../../fuzz-wordlists/fuzz.txt";

import { buildAlert, type Alert } from "./alerts.js";
import { insertFinding } from "../db/queries/findings.js";

export type FuzzCategory = "api" | "directories" | "files" | "fuzz";

const WORDLISTS: Record<FuzzCategory, string> = {
  api: apiTxt,
  directories: directoriesTxt,
  files: filesTxt,
  fuzz: fuzzTxt,
};

export interface FuzzProfile {
  categories: FuzzCategory[];
  maxRequests: number;
  maxConcurrency: number;
  delayMs: number;
  timeoutMs: number;
  maxResponseBytes: number;
  stopOn429: boolean;
}

export const FUZZ_PROFILE: FuzzProfile = {
  categories: ["api", "directories", "files", "fuzz"],
  maxRequests: 200,
  maxConcurrency: 2,
  delayMs: 250,
  timeoutMs: 8_000,
  maxResponseBytes: 256 * 1024,
  stopOn429: true,
};

export interface FuzzResult {
  url: string;
  status: number;
  contentType: string | null;
  contentLength: number;
  title: string | null;
  bodyHash: string;
  classification: string;
  isSensitive: boolean;
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
  // URL-encode-safe: letters, digits, _ - / . ~ : @ ! $ & ' ( ) * + , ; = %
  if (!/^[A-Za-z0-9_\-\/.~:@!$&'()*+,;=%]+$/.test(v)) return null;
  return v;
}

/**
 * Classification heuristics: which responses are worth alerting on?
 * 404s and auth walls are ignored; interesting files (env/config/backup/
 * admin/api responses) are flagged as sensitive.
 */
function classifyResponse(status: number, contentType: string, url: string, body: string): { classification: string; isSensitive: boolean } {
  const ct = contentType.toLowerCase();
  if (status === 404 || status === 410) return { classification: "not_found", isSensitive: false };
  if (status === 401 || status === 403) return { classification: "auth_required", isSensitive: false };

  const urlLc = url.toLowerCase();
  const bodyLc = body.slice(0, 10_000).toLowerCase();

  const sensitiveFilePatterns = [
    /\.env($|\?)/, /\.git\//, /\.config($|\.)/, /\.bak($|\.)/, /\.old($|\.)/,
    /\.sql($|\.)/, /\.zip($|\.)/, /\.tar($|\.gz$)/, /\.7z($|\.)/, /\.rar($|\.)/,
    /backup/, /dump/, /id_rsa/, /\.pem($|\.)/, /\.key($|\.)/, /credentials/,
    /phpinfo/, /\.ini($|\.)/, /web\.config/, /\.DS_Store/,
  ];
  if (sensitiveFilePatterns.some((re) => re.test(urlLc)) && status < 400) {
    return { classification: "sensitive_file", isSensitive: true };
  }

  if (/\.env/.test(urlLc) && /(db_|database|password|secret|api[_-]?key)\s*=/.test(bodyLc)) {
    return { classification: "exposed_environment", isSensitive: true };
  }

  if (status === 200 && /application\/(json|xml)/.test(ct)) {
    return { classification: "new_api_route", isSensitive: true };
  }

  if (status === 200 && /text\/html/.test(ct)) {
    const adminRe = /admin|login|dashboard|signin|console|cpanel|manager|wp-login/i;
    if (adminRe.test(urlLc) || adminRe.test((body.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)?.[1] ?? ""))) {
      return { classification: "admin_panel", isSensitive: true };
    }
    return { classification: "new_endpoint", isSensitive: false };
  }

  if (status >= 500) return { classification: "server_error", isSensitive: false };
  return { classification: "requires_review", isSensitive: false };
}

/**
 * Fuzz one host with the next slice of wordlist entries. `offset` is the
 * per-host cursor (kept by the caller in KV); returns the new offset.
 */
export async function runFuzzChunk(
  env: Env,
  baseUrl: string,
  targetId: string,
  scope: CompiledScope,
  offset: number,
  profile: FuzzProfile = FUZZ_PROFILE,
): Promise<{ results: FuzzResult[]; alerts: Alert[]; newOffset: number; done: boolean }> {
  const all: string[] = [];
  for (const cat of profile.categories) {
    for (const line of WORDLISTS[cat].split("\n")) {
      const sanitized = sanitizeWordlistEntry(line);
      if (sanitized) all.push(sanitized.startsWith("/") ? sanitized : `/${sanitized}`);
    }
  }
  // Deduplicate while keeping order.
  const seen = new Set<string>();
  const entries = all.filter((e) => (seen.has(e) ? false : (seen.add(e), true)));

  const start = Math.min(offset, entries.length);
  const slice = entries.slice(start, start + profile.maxRequests);

  const results: FuzzResult[] = [];
  const alerts: Alert[] = [];
  let consecutiveErrors = 0;

  let i = 0;
  const workers = Array.from({ length: profile.maxConcurrency }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= slice.length) break;
      if (consecutiveErrors >= 5) break;
      const path = slice[idx]!;

      const url = joinUrl(baseUrl, path);
      if (!url) continue;
      if (!checkUrlInScope(scope, url).allowed) continue;

      try {
        const r = await safeFetch(env, url, {
          scope,
          method: "GET",
          timeoutMs: profile.timeoutMs,
          maxBytes: profile.maxResponseBytes,
          userAgent: env.USER_AGENT,
          followRedirects: false,
        });
        if (r.status === 429 && profile.stopOn429) { consecutiveErrors = 99; break; }
        if (r.status >= 500) { consecutiveErrors++; continue; }
        consecutiveErrors = 0;

        const text = new TextDecoder().decode(r.body);
        const bodyHash = await sha256(text);
        const title = (text.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)?.[1] ?? "").trim() || null;
        const { classification, isSensitive } = classifyResponse(
          r.status, r.headers["content-type"] ?? "", url, text,
        );

        results.push({
          url,
          status: r.status,
          contentType: r.headers["content-type"] ?? null,
          contentLength: r.body.byteLength,
          title,
          bodyHash,
          classification,
          isSensitive,
        });

        if (isSensitive) {
          const fingerprint = await sha256(`fuzz|${url}|${r.status}`);
          const inserted = await insertFinding(env.DB, {
            targetId,
            affectedUrl: url,
            findingType: classification,
            title: `Sensitive path discovered: ${path}`,
            summary:
              `Wordlist fuzzing found a sensitive response.\n\n` +
              `URL: ${url}\nStatus: ${r.status}\nContent-Type: ${r.headers["content-type"] ?? "unknown"}\n` +
              `Length: ${r.body.byteLength} bytes\nTitle: ${title ?? "—"}\nClassification: ${classification}`,
            severity: classification === "exposed_environment" ? "critical" : "high",
            detectionSource: "wordlist-fuzzer",
            detectionMethod: "wordlist-fuzzing",
            fingerprint,
            metadata: { url, status: r.status, classification, content_length: r.body.byteLength },
          });
          if (inserted) {
            alerts.push(buildAlert("new_fuzz_endpoint", targetId, {
              asset_value: url,
              title: `Sensitive path found: ${path} (${classification})`,
              summary:
                `Wordlist fuzzing found a sensitive response on ${baseUrl}.\n\n` +
                `URL: ${url}\nStatus: ${r.status}\nClassification: ${classification}\nTitle: ${title ?? "—"}`,
              metadata: { url, status: r.status, classification },
            }, classification === "exposed_environment" ? "critical" : "high"));
          }
        }

        // Throttle between requests.
        await new Promise((resolve) => setTimeout(resolve, profile.delayMs));
      } catch {
        consecutiveErrors++;
      }
    }
  });
  await Promise.all(workers);

  const newOffset = start + slice.length;
  return { results, alerts, newOffset, done: newOffset >= entries.length };
}
