/**
 * Secret detection and redaction.
 *
 * This module is the single choke point that prevents credentials from ever
 * reaching a log sink, a Telegram message, an R2 object or a generated report.
 *
 * Two responsibilities, deliberately separated:
 *
 *   1. `redactString` / `redactDeep` - aggressive, pattern-based scrubbing used
 *      by the logger and by every notification/report renderer. When in doubt
 *      these over-redact; a truncated log line is cheap, a leaked key is not.
 *
 *   2. `scanForSecrets` - high-confidence candidate detection used by the
 *      JavaScript analyser and the wordlist module. Only emits a finding when a
 *      pattern is specific enough to be worth a human's attention, and only
 *      ever exposes a salted one-way fingerprint plus a location, never the
 *      value.
 *
 * Hard rules enforced here:
 *   - The full value of a detected secret is never returned to a caller.
 *   - `scanForSecrets` returns `redacted` previews capped at a few characters.
 *   - Fingerprints are salted; the salt lives in a Worker secret, so a leaked
 *     fingerprint cannot be brute-forced offline against a small keyspace.
 */

/** Marker substituted for anything redacted. Stable so tests can assert on it. */
export const REDACTED = '[REDACTED]';

/** How many leading characters of a secret may be echoed back for triage. */
const PREVIEW_CHARS = 4;

export interface SecretPattern {
  /** Stable identifier persisted on the finding, e.g. `aws_access_key_id`. */
  readonly id: string;
  readonly label: string;
  readonly regex: RegExp;
  /** 0..1. Below ~0.7 the candidate is reported as low confidence only. */
  readonly confidence: number;
  /** Rough severity hint before business context is applied. */
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Ordered most-specific first. Ordering matters: the AWS secret access key
 * pattern would otherwise also match a generic 40-char base64 blob, so the
 * generic patterns are evaluated last.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'aws_access_key_id',
    label: 'AWS access key ID',
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    confidence: 0.97,
    severity: 'critical',
  },
  {
    id: 'google_api_key',
    label: 'Google API key',
    // Google keys are `AIza` + 35 chars; the trailing boundary is deliberately
    // loose so re-issued / longer keys are still caught.
    regex: /\bAIza[0-9A-Za-z_-]{35,}/g,
    confidence: 0.95,
    severity: 'high',
  },
  {
    id: 'stripe_secret_key',
    label: 'Stripe secret key',
    regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g,
    confidence: 0.95,
    severity: 'critical',
  },
  {
    id: 'github_token',
    label: 'GitHub token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b/g,
    confidence: 0.96,
    severity: 'critical',
  },
  {
    id: 'github_pat',
    label: 'GitHub fine-grained PAT',
    regex: /\bgithub_pat_[0-9A-Za-z_]{60,}\b/g,
    confidence: 0.96,
    severity: 'critical',
  },
  {
    id: 'slack_token',
    label: 'Slack token',
    regex: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g,
    confidence: 0.93,
    severity: 'high',
  },
  {
    id: 'slack_webhook',
    label: 'Slack incoming webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{8,}\/[A-Z0-9]{8,}\/[0-9A-Za-z]{20,}/g,
    confidence: 0.95,
    severity: 'high',
  },
  {
    id: 'telegram_bot_token',
    label: 'Telegram bot token',
    regex: /\b\d{8,12}:[0-9A-Za-z_-]{30,}\b/g,
    confidence: 0.9,
    severity: 'critical',
  },
  {
    id: 'private_key_block',
    label: 'PEM private key',
    // Matches the WHOLE PEM block so the base64 body is redacted too, not just
    // the header line.
    regex:
      /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    confidence: 0.99,
    severity: 'critical',
  },
  {
    id: 'jwt',
    label: 'JSON Web Token',
    regex: /\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b/g,
    confidence: 0.88,
    severity: 'high',
  },
  {
    id: 'basic_auth_url',
    label: 'Credentials embedded in URL',
    regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]{1,64}:[^\s/@]{6,}@/gi,
    confidence: 0.85,
    severity: 'critical',
  },
  {
    id: 'database_url',
    label: 'Database connection string',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql):\/\/[^\s"'<>]{10,}/gi,
    confidence: 0.85,
    severity: 'critical',
  },
  {
    id: 'sendgrid_key',
    label: 'SendGrid API key',
    regex: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{22}\b/g,
    confidence: 0.94,
    severity: 'high',
  },
  {
    id: 'npm_token',
    label: 'npm token',
    regex: /\bnpm_[0-9A-Za-z]{36}\b/g,
    confidence: 0.94,
    severity: 'high',
  },
  {
    id: 'openai_key',
    label: 'OpenAI API key',
    regex: /\bsk-[0-9A-Za-z_-]{20,}T3BlbkFJ[0-9A-Za-z_-]{20,}\b/g,
    confidence: 0.93,
    severity: 'high',
  },
  {
    id: 'authorization_bearer',
    label: 'Bearer token in source',
    regex: /\bBearer\s+[0-9A-Za-z._~+/-]{20,}=*/g,
    confidence: 0.8,
    severity: 'high',
  },
  {
    id: 'assigned_secret',
    label: 'Assigned secret-like literal',
    // Requires a secret-ish key name AND a long opaque literal, which keeps the
    // false-positive rate tolerable compared with matching bare hex strings.
    regex:
      /(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd|pwd|private[_-]?key)["']?\s*[:=]\s*["'][0-9A-Za-z!@#$%^&*()_+\-=[\]{};:,.?/~]{16,}["']/gi,
    confidence: 0.72,
    severity: 'high',
  },
] as const;

/**
 * Keys whose values are always redacted when walking an object, regardless of
 * the value's shape. This catches credentials that do not match a byte pattern
 * (short passwords, session cookies, opaque API keys).
 */
const SENSITIVE_KEY_PATTERN =
  /^(?:pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|session[_-]?(?:id|token)?|cookie|set[_-]?cookie|authorization|proxy[_-]?authorization|private[_-]?key|signing[_-]?key|encryption[_-]?key|token|credential|credentials|bearer|csrf|xsrf|nonce|salt|jwt)$/i;

/** Header names that must never be logged or echoed. */
const SENSITIVE_HEADER_PATTERN =
  /^(?:authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-amz-security-token|x-goog-api-key|api-key|private-token|x-gitlab-token)$/i;

export const isSensitiveKey = (key: string): boolean => SENSITIVE_KEY_PATTERN.test(key.trim());
export const isSensitiveHeader = (name: string): boolean =>
  SENSITIVE_HEADER_PATTERN.test(name.trim());

/** Replaces every known high-confidence secret pattern inside a string. */
export function redactString(input: string): string {
  let output = input;
  for (const pattern of SECRET_PATTERNS) {
    // Patterns are module-level and carry the /g flag, so lastIndex must be
    // reset before every use or successive calls would skip matches.
    pattern.regex.lastIndex = 0;
    output = output.replace(pattern.regex, REDACTED);
  }
  return output;
}

/**
 * Deep redaction of arbitrary data before it is logged, stored as evidence or
 * rendered into a report.
 *
 * Behaviour:
 *   - Values under a sensitive key are replaced wholesale.
 *   - Strings are pattern-scrubbed.
 *   - Depth is bounded so a cyclic structure cannot hang a Worker.
 *   - Typed arrays / ArrayBuffers are summarised, never dumped.
 */
export function redactDeep<T>(value: T, depth = 0, seen: WeakSet<object> = new WeakSet()): unknown {
  if (depth > 12) return '[DEPTH_LIMIT]';
  if (value === null || value === undefined) return value;

  const primitive = typeof value;
  if (primitive === 'string') return redactString(value as unknown as string);
  if (primitive === 'number' || primitive === 'boolean' || primitive === 'bigint') return value;
  if (primitive === 'function' || primitive === 'symbol') return '[UNSERIALISABLE]';

  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return `[BINARY ${(value as ArrayBuffer).byteLength ?? 0} bytes]`;
  }
  if (value instanceof Date) return value.toISOString();
  if (value instanceof URL) return redactString(value.toString());

  // Cycle guard: a self-referential object would otherwise recurse until the
  // depth limit (or blow up on a wide cyclic graph).
  const asObject = value as unknown as object;
  if (seen.has(asObject)) return '[DEPTH_LIMIT]';
  seen.add(asObject);

  if (Array.isArray(value)) {
    const limit = 200;
    const head = value.slice(0, limit).map((entry) => redactDeep(entry, depth + 1, seen));
    if (value.length > limit) head.push(`[${value.length - limit} more items]`);
    return head;
  }

  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    out[key] = isSensitiveKey(key) ? REDACTED : redactDeep(entry, depth + 1, seen);
  }
  return out;
}

/**
 * Redacts a headers object (Fetch `Headers`, plain object or array of pairs).
 * Returns a plain, case-preserving record safe to store as evidence.
 */
export function redactHeaders(
  headers: Headers | Record<string, string | string[]> | Array<[string, string]>,
): Record<string, string> {
  const entries: Array<[string, string]> = [];

  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    headers.forEach((value, key) => entries.push([key, value]));
  } else if (Array.isArray(headers)) {
    for (const [key, value] of headers) entries.push([key, value]);
  } else {
    for (const [key, value] of Object.entries(headers)) {
      entries.push([key, Array.isArray(value) ? value.join(', ') : value]);
    }
  }

  const out: Record<string, string> = {};
  for (const [key, value] of entries) {
    if (isSensitiveHeader(key)) {
      out[key] = REDACTED;
    } else if (/^set-cookie$/i.test(key)) {
      out[key] = REDACTED;
    } else {
      out[key] = redactString(value);
    }
  }
  return out;
}


export interface SecretCandidate {
  /** Pattern identifier, e.g. `aws_access_key_id`. */
  readonly patternId: string;
  readonly label: string;
  readonly confidence: number;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
  /** Redacted preview: first 4 chars then a fixed mask. Never the full value. */
  readonly preview: string;
  /** 1-based line number when the source is line-addressable. */
  readonly line: number;
  /** 1-based column of the match start. */
  readonly column: number;
  /** Character length of the original match, useful for triage without value. */
  readonly length: number;
  /** Salted one-way fingerprint used for dedupe. Requires the salt secret. */
  readonly fingerprint: string;
  /** Byte offset in the source, so a caller can build a bounded excerpt. */
  readonly offset: number;
}

export interface ScanForSecretsOptions {
  /** Salt for fingerprints. Callers pass the Worker secret, never a literal. */
  readonly salt: string;
  /** Hard ceiling on candidates returned per document. Default 200. */
  readonly maxCandidates?: number;
  /** Only report patterns at or above this confidence. Default 0.7. */
  readonly minConfidence?: number;
}

const DEFAULT_MIN_CONFIDENCE = 0.7;
const DEFAULT_MAX_CANDIDATES = 200;

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** SHA-256 hex of an arbitrary UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Salted fingerprint of a secret value.
 *
 * The salt is a Worker secret, so identical secrets in two different
 * deployments produce different fingerprints and an attacker who obtains a
 * fingerprint cannot dictionary-attack it without also holding the salt.
 */
export async function fingerprintSecret(value: string, salt: string): Promise<string> {
  return sha256Hex(`${salt}\u0000${value}`);
}

/**
 * Produces a safe preview: at most `PREVIEW_CHARS` leading characters plus a
 * fixed-length mask that reveals nothing about the length beyond a coarse
 * bucket. Operators can recognise *which* key leaked without ever seeing it.
 */
export function redactedPreview(value: string): string {
  const head = value.slice(0, PREVIEW_CHARS);
  return `${head}${'*'.repeat(Math.min(12, Math.max(4, value.length - PREVIEW_CHARS)))}`;
}

/** Byte offset -> 1-based line/column lookup for a document. */
function lineIndexFor(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset; i += 1) {
    if (source.charCodeAt(i) === 10) {
      line += 1;
      lineStart = i + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

/**
 * Detects high-confidence secret candidates in a text document (typically a
 * JavaScript file, a configuration file or a wordlist hit).
 *
 * Guarantees:
 *   - The full matched value is never placed on the returned candidate.
 *   - Results are de-duplicated by fingerprint so the same key echoed in
 *     multiple bundles yields one candidate.
 *   - Bounded by `maxCandidates` so a pathological file cannot exhaust memory
 *     or flood the findings table.
 */
export async function scanForSecrets(
  source: string,
  options: ScanForSecretsOptions,
): Promise<SecretCandidate[]> {
  const minConfidence = options.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
  const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;

  if (!options.salt) {
    throw new Error('scanForSecrets requires a non-empty salt; refusing to fingerprint unsalted.');
  }

  const seen = new Set<string>();
  const candidates: SecretCandidate[] = [];

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.confidence < minConfidence) continue;
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(source)) !== null) {
      const value = match[0];
      // Guard against zero-length matches causing an infinite loop.
      if (value.length === 0) {
        pattern.regex.lastIndex += 1;
        continue;
      }

      const fingerprint = await fingerprintSecret(value, options.salt);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);

      const { line, column } = lineIndexFor(source, match.index);
      candidates.push({
        patternId: pattern.id,
        label: pattern.label,
        confidence: pattern.confidence,
        severity: pattern.severity,
        preview: redactedPreview(value),
        line,
        column,
        length: value.length,
        fingerprint,
        offset: match.index,
      });

      if (candidates.length >= maxCandidates) {
        return candidates.sort((a, b) => a.offset - b.offset);
      }
    }
  }

  return candidates.sort((a, b) => a.offset - b.offset);
}

/**
 * Verifies a stored evidence blob against its recorded hash. Used by the
 * evidence integrity check and the chain-of-custody metadata.
 */
export async function verifyIntegrity(content: string, expectedHash: string): Promise<boolean> {
  const actual = await sha256Hex(content);
  if (actual.length !== expectedHash.length) return false;
  // Constant-time-ish comparison: avoids early exit on first differing char.
  let diff = 0;
  for (let i = 0; i < actual.length; i += 1) {
    diff |= actual.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  }
  return diff === 0;
}
