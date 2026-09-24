// src/modules/js-analyzer.ts
// Discovers, fetches, hashes, and diffs JavaScript files for an authorized
// HTTP asset. Extracts endpoint-like strings, GraphQL paths, and high-confidence
// secret candidates (which are redacted before storage).
//
// Returns a list of `Alert` objects — one per new JS file, changed JS file,
// new API endpoint, or detected secret — so the scan consumer can enqueue
// notifications without re-deriving them.

import type { Env } from "../env.js";
import type { CompiledScope } from "../security/scope.js";
import { checkUrlInScope } from "../security/scope.js";
import { safeFetch } from "../security/ssrf.js";
import { upsertJavascriptFile, insertApiEndpoint } from "../db/queries/assets.js";
import { insertFinding } from "../db/queries/findings.js";
import { sha256 } from "../crypto/hash.js";
import { redactWithFingerprints } from "../security/redaction.js";
import { LIMITS } from "../constants.js";
import { joinUrl } from "../utils/url.js";
import { buildAlert, type Alert } from "./alerts.js";

const MAX_JS_FILES = LIMITS.MAX_JS_FILES_PER_TARGET;

export interface JsAnalysisResult {
  alerts: Alert[];
  filesDiscovered: number;
  filesModified: number;
  endpointsExtracted: number;
  secretsDetected: number;
  redactedSecretsStored: number;
  errors: string[];
}

export async function analyzeJsForAsset(
  env: Env,
  targetId: string,
  assetId: string,
  baseUrl: string,
  scope: CompiledScope,
  redactionSalt: string,
): Promise<JsAnalysisResult> {
  const alerts: Alert[] = [];
  const out: JsAnalysisResult = {
    alerts,
    filesDiscovered: 0, filesModified: 0, endpointsExtracted: 0,
    secretsDetected: 0, redactedSecretsStored: 0, errors: [],
  };

  // 1. Fetch the HTML at baseUrl to discover <script src="..."> references.
  const scopeCheck = checkUrlInScope(scope, baseUrl);
  if (!scopeCheck.allowed) { out.errors.push(`base URL out of scope: ${scopeCheck.reason}`); return out; }

  let htmlBytes: Uint8Array;
  try {
    const r = await safeFetch(env, baseUrl, {
      scope, method: "GET",
      timeoutMs: 15_000, maxBytes: LIMITS.MAX_RESPONSE_BYTES,
      userAgent: env.USER_AGENT,
    });
    htmlBytes = r.body;
  } catch (err) {
    out.errors.push(`fetch html: ${String(err)}`);
    return out;
  }

  const scriptUrls = extractScriptUrls(baseUrl, htmlBytes);
  let i = 0;
  for (const jsUrl of scriptUrls) {
    if (i >= MAX_JS_FILES) { out.errors.push(`hit MAX_JS_FILES_PER_TARGET limit (${MAX_JS_FILES})`); break; }
    i++;
    const scopeOk = checkUrlInScope(scope, jsUrl);
    if (!scopeOk.allowed) continue;

    try {
      const r = await safeFetch(env, jsUrl, {
        scope, method: "GET",
        timeoutMs: 15_000, maxBytes: LIMITS.MAX_JS_FILE_BYTES,
        userAgent: env.USER_AGENT,
      });
      const body = r.body;
      if (body.byteLength === 0) continue;
      const bodyText = toText(body);
      const hash = await sha256(bodyText);

      const jsRes = await upsertJavascriptFile(
        env.DB, assetId, jsUrl, hash, body.byteLength,
        r.headers["etag"] ?? null,
        r.headers["last-modified"] ?? null,
        r.headers["content-type"] ?? null,
      );

      if (jsRes.created) {
        out.filesDiscovered++;
        alerts.push(buildAlert("new_javascript_file", targetId, {
          asset_id: assetId,
          asset_value: jsUrl,
          title: `New JavaScript file discovered: ${truncateUrl(jsUrl)}`,
          summary:
            `A new JavaScript file was discovered on ${baseUrl}.\n\n` +
            `URL: ${jsUrl}\nSize: ${body.byteLength} bytes\nSHA-256: ${hash.slice(0, 16)}…\nContent-Type: ${r.headers["content-type"] ?? "unknown"}`,
          metadata: { url: jsUrl, sha256: hash, size_bytes: body.byteLength, content_type: r.headers["content-type"] ?? null },
        }));
      } else if (jsRes.previous_sha) {
        out.filesModified++;
        alerts.push(buildAlert("javascript_changed", targetId, {
          asset_id: assetId,
          asset_value: jsUrl,
          title: `JavaScript file changed: ${truncateUrl(jsUrl)}`,
          summary:
            `A JavaScript file's content hash changed.\n\n` +
            `URL: ${jsUrl}\nPrevious SHA-256: ${jsRes.previous_sha.slice(0, 16)}…\nCurrent SHA-256: ${hash.slice(0, 16)}…\nSize: ${body.byteLength} bytes\n\nManual review required — this often indicates a deployment.`,
          metadata: {
            url: jsUrl,
            previous_sha256: jsRes.previous_sha,
            current_sha256: hash,
            size_bytes: body.byteLength,
          },
        }));
      }

      // Endpoint extraction — observations only
      const endpoints = extractEndpoints(bodyText, jsUrl);
      for (const ep of endpoints) {
        const epRes = await insertApiEndpoint(env.DB, assetId, ep.method, ep.path, [], "js-extraction");
        if (epRes.inserted) {
          out.endpointsExtracted++;
          alerts.push(buildAlert("new_api_endpoint", targetId, {
            asset_id: assetId,
            asset_value: `${ep.method} ${jsUrl}${ep.path}`,
            title: `New API endpoint extracted: ${ep.method} ${ep.path}`,
            summary:
              `A new API endpoint-like string was extracted from a JavaScript file.\n\n` +
              `Source JS: ${jsUrl}\nMethod: ${ep.method}\nPath: ${ep.path}\nExtraction: ${ep.source}\n\n` +
              `This is an observation — the endpoint was not invoked. Manual verification required.`,
            metadata: { method: ep.method, path: ep.path, source_js: jsUrl, extraction_method: ep.source },
          }));
        }
      }

      // Secret detection — values are NEVER stored. Only salted fingerprints.
      const { secrets } = await redactWithFingerprints(bodyText, redactionSalt);
      out.secretsDetected += secrets.length;
      for (const s of secrets) {
        const fingerprint = await sha256(`secret|${jsUrl}|${s.type}|${s.fingerprint}`);
        const findingId = await insertFinding(env.DB, {
          targetId,
          assetId,
          findingType: "exposed_secret_candidate",
          title: `Possible ${s.type} detected in JavaScript`,
          summary: `A high-confidence ${s.type} pattern was detected at line ${s.line} of ${jsUrl}. Value has been redacted; fingerprint stored. Manual review required.`,
          severity: "high",
          affectedAsset: jsUrl,
          affectedUrl: jsUrl,
          detectionSource: "js-analysis",
          detectionMethod: "regex-detection",
          confidence: s.confidence,
          fingerprint,
          metadata: { js_url: jsUrl, line: s.line, secret_type: s.type, value_fingerprint: s.fingerprint },
        });
        if (!findingId) continue; // already known — don't re-alert
        out.redactedSecretsStored++;

        alerts.push(buildAlert("new_secret_candidate", targetId, {
          asset_id: assetId,
          asset_value: `${jsUrl}:${s.line}`,
          title: `Possible ${s.type} in JavaScript (line ${s.line})`,
          summary:
            `A high-confidence secret pattern was detected in a JavaScript file.\n\n` +
            `Source JS: ${jsUrl}\nLine: ${s.line}\nType: ${s.type}\nConfidence: ${(s.confidence * 100).toFixed(0)}%\nFingerprint: ${s.fingerprint.slice(0, 16)}…\n\n` +
            `The full value has been redacted and only the salted fingerprint is stored. Manual review required before any further action.`,
          metadata: {
            finding_id: findingId,
            js_url: jsUrl,
            line: s.line,
            secret_type: s.type,
            confidence: s.confidence,
            fingerprint: s.fingerprint,
          },
        }, "high"));
      }
    } catch (err) {
      out.errors.push(`fetch ${jsUrl}: ${String(err)}`);
    }
  }

  return out;
}

function truncateUrl(url: string, max = 80): string {
  return url.length <= max ? url : url.slice(0, max - 1) + "…";
}

function toText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

const SCRIPT_SRC_REGEX = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
const MODULE_IMPORT_REGEX = /import\s+(?:[\w*\s{},]+from\s+)?["']([^"']+)["']/g;
const DYNAMIC_IMPORT_REGEX = /import\(["']([^"']+)["']\)/g;

export function extractScriptUrls(baseUrl: string, htmlBytes: Uint8Array): string[] {
  const html = toText(htmlBytes);
  const urls = new Set<string>();
  let m: RegExpExecArray | null;
  SCRIPT_SRC_REGEX.lastIndex = 0;
  while ((m = SCRIPT_SRC_REGEX.exec(html)) !== null) {
    const u = joinUrl(baseUrl, m[1]!);
    if (u && (u.startsWith("http://") || u.startsWith("https://"))) urls.add(u);
  }
  MODULE_IMPORT_REGEX.lastIndex = 0;
  while ((m = MODULE_IMPORT_REGEX.exec(html)) !== null) {
    const u = joinUrl(baseUrl, m[1]!);
    if (u && (u.startsWith("http://") || u.startsWith("https://"))) urls.add(u);
  }
  DYNAMIC_IMPORT_REGEX.lastIndex = 0;
  while ((m = DYNAMIC_IMPORT_REGEX.exec(html)) !== null) {
    const u = joinUrl(baseUrl, m[1]!);
    if (u && (u.startsWith("http://") || u.startsWith("https://"))) urls.add(u);
  }
  return Array.from(urls).slice(0, MAX_JS_FILES);
}

/**
 * Extracts endpoint-like strings from a JS body. Heuristic: matches paths
 * starting with `/api`, `/v1`, `/v2`, `/graphql`, `/auth`, `/oauth`, etc.
 * Observations only — never invoked automatically.
 */
const PATH_REGEXES = [
  /["'`](\/(?:api|v1|v2|graphql|auth|oauth|admin|user|account|billing|payments?|webhooks?|sessions?|tokens?|uploads?)\/[A-Za-z0-9_\-\/{}.:]+)["'`]/g,
];

const ENDPOINT_METHOD_REGEX = /\b(?:fetch|axios|xhr|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*(?:\.\s*\w+\s*)?\(\s*["'`]([^"'`]+)["'`]/gi;

export function extractEndpoints(jsBody: string, _sourceUrl: string): { method: string; path: string; source: string }[] {
  const out: { method: string; path: string; source: string }[] = [];
  const seen = new Set<string>();
  for (const re of PATH_REGEXES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(jsBody)) !== null) {
      const p = m[1]!;
      if (seen.has(p)) continue;
      seen.add(p);
      out.push({ method: "GET", path: p, source: "js-regex-extraction" });
    }
  }
  ENDPOINT_METHOD_REGEX.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ENDPOINT_METHOD_REGEX.exec(jsBody)) !== null) {
    const p = m[1]!;
    if (p.startsWith("http://") || p.startsWith("https://")) continue;
    if (p.startsWith("/")) {
      if (seen.has(p)) continue;
      seen.add(p);
      out.push({ method: "GET", path: p, source: "js-call-extraction" });
    }
  }
  return out;
}
