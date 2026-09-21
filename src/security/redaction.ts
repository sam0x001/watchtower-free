// src/security/redaction.ts
// Backwards-compatible wrapper around watchtower1's `lib/redact.ts`.
// Exposes the API the rest of the codebase expects (`detectSecrets`,
// `redactSync`, `redactWithFingerprints`, `containsLikelySecret`,
// `redactValue`) while delegating to watchtower1's more thorough
// implementation, which uses salted fingerprints (a real security improvement
// over the v1 unsalted design).

import {
  redactString,
  redactDeep,
  redactHeaders,
  scanForSecrets,
  fingerprintSecret,
  redactedPreview,
  SECRET_PATTERNS,
  REDACTED,
  isSensitiveKey,
  type SecretCandidate,
} from "../lib/redact.js";

// ---------------------------------------------------------------------------
// Legacy types & API
// ---------------------------------------------------------------------------

export type SecretType = string;

export interface DetectedSecret {
  type: SecretType;
  value: string;
  redacted: string;
  fingerprint: string;
  line: number;
  column: number;
  confidence: number;
}

const DEFAULT_SALT = "watchtower-default-redaction-salt-v2";

/**
 * Detects secrets in a text blob. Returns matches WITHOUT the full value —
 * callers receive only a redacted preview and (if `salt` provided) a
 * salted fingerprint.
 *
 * NOTE: `lib/redact.ts` deliberately does NOT expose the full secret value
 * on `SecretCandidate`. This wrapper preserves that invariant — `value` is
 * always the redacted preview, never the original.
 */
export async function detectSecrets(
  text: string,
  salt: string = DEFAULT_SALT,
): Promise<DetectedSecret[]> {
  const candidates = await scanForSecrets(text, { salt });
  return candidates.map((c) => ({
    type: c.patternId,
    value: c.preview,
    redacted: REDACTED,
    fingerprint: c.fingerprint,
    line: c.line,
    column: c.column,
    confidence: c.confidence,
  }));
}

/**
 * Synchronous redaction. Returns the redacted string and a list of detected
 * secrets (without full values or fingerprints — those require the salt).
 */
export function redactSync(text: string): { redacted: string; secrets: DetectedSecret[] } {
  const redacted = redactString(text);
  // Synchronous secrets list: pattern id + line only — no fingerprint.
  const secrets: DetectedSecret[] = [];
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    let line = 1;
    let lastIdx = 0;
    while ((m = pattern.regex.exec(text)) !== null) {
      const v = m[0];
      if (!v) {
        pattern.regex.lastIndex += 1;
        continue;
      }
      // Compute line number from the match index.
      for (let i = lastIdx; i < m.index; i++) if (text.charCodeAt(i) === 10) line++;
      lastIdx = m.index;
      secrets.push({
        type: pattern.id,
        value: redactedPreview(v),
        redacted: REDACTED,
        fingerprint: "", // requires async + salt; not available synchronously
        line,
        column: 0,
        confidence: pattern.confidence,
      });
    }
  }
  return { redacted, secrets };
}

/**
 * Async redaction that also produces salted fingerprints for every detected
 * secret. Used by the JS analyzer when storing finding records.
 */
export async function redactWithFingerprints(
  text: string,
  salt: string = DEFAULT_SALT,
): Promise<{ redacted: string; secrets: DetectedSecret[] }> {
  const { redacted } = redactSync(text);
  const secrets = await detectSecrets(text, salt);
  return { redacted, secrets };
}

/**
 * Redacts a single value (e.g. an `Authorization` header) and produces a
 * salted fingerprint.
 */
export async function redactValue(
  value: string,
  type: SecretType = "api_key_generic",
  salt: string = DEFAULT_SALT,
): Promise<{ redacted: string; fingerprint: string }> {
  const fingerprint = await fingerprintSecret(value, salt);
  return { redacted: `<redacted:${type}>`, fingerprint };
}

export function containsLikelySecret(text: string): boolean {
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(text)) return true;
  }
  return false;
}

// Re-export watchtower1's deeper API for direct callers.
export {
  redactString,
  redactDeep,
  redactHeaders,
  scanForSecrets,
  fingerprintSecret,
  redactedPreview,
  SECRET_PATTERNS,
  REDACTED,
  isSensitiveKey,
};
export type { SecretCandidate };
