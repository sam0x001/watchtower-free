// src/crypto/hmac.ts
// Short-lived signed tokens (runner job payloads, signed callback URLs).

import { hmacSha256B64Url, base64UrlEncode, base64UrlDecode } from "./hash.js";

export interface SignedToken {
  payload: string; // base64url JSON
  sig: string;
  exp: number;     // epoch ms
}

export async function signToken(
  key: string,
  payload: Record<string, unknown>,
  ttlSeconds: number,
): Promise<string> {
  const exp = Date.now() + ttlSeconds * 1000;
  const body = { ...payload, exp };
  const payloadB64 = base64UrlEncode(JSON.stringify(body));
  const sig = await hmacSha256B64Url(key, payloadB64);
  return `${payloadB64}.${sig}`;
}

export async function verifyToken(
  key: string,
  token: string,
  opts: { maxSkewSeconds?: number } = {},
): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts as [string, string];
  const expected = await hmacSha256B64Url(key, payloadB64);
  // constant time-ish comparison via length + early-reject false
  if (expected.length !== sig.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;

  const json = base64UrlDecode(payloadB64);
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(json);
  } catch {
    return null;
  }
  const exp = body["exp"];
  if (typeof exp !== "number") return null;
  const skewMs = (opts.maxSkewSeconds ?? 5) * 1000;
  if (Date.now() > exp + skewMs) return null;
  return body;
}

/** Verify a webhook signature using HMAC-SHA256 with a known header name. */
export async function verifyWebhookSignature(
  key: string,
  body: string,
  signatureHex: string,
): Promise<boolean> {
  const expected = await hmacSha256Hex(key, body);
  if (expected.length !== signatureHex.length) return false;
  let diff = 0;
  for (let i = 0; i < signatureHex.length; i++) {
    diff |= expected.charCodeAt(i) ^ signatureHex.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(key: string, message: string): Promise<string> {
  // reuse hash.ts logic but as hex
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  const bytes = new Uint8Array(sig);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}
