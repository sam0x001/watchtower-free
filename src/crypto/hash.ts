// src/crypto/hash.ts
// SHA-256, HMAC-SHA256, and base64url helpers using Web Crypto.

const enc = new TextEncoder();
const dec = new TextDecoder();

export async function sha256(input: string | ArrayBuffer | Uint8Array): Promise<string> {
  const data = typeof input === "string"
    ? enc.encode(input)
    : input instanceof Uint8Array
      ? input
      : input;
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return bufferToHex(digest);
}

export async function hmacSha256(key: string, message: string): Promise<string> {
  const keyBytes = enc.encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return bufferToHex(sig);
}

export async function hmacSha256B64Url(key: string, message: string): Promise<string> {
  const sig = await hmacSha256Raw(key, message);
  return bufferToBase64Url(sig);
}

export async function hmacSha256Raw(key: string, message: string): Promise<ArrayBuffer> {
  const keyBytes = enc.encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
}

export function bufferToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

export function bufferToBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlEncode(input: string): string {
  return btoa(input).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  return atob(input.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

export function randomBytes(n: number): Uint8Array {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return arr;
}

export function randomId(prefix = "", length = 16): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[bytes[i]! % alphabet.length]!;
  return prefix ? `${prefix}_${out}` : out;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i]! ^ bBytes[i]!;
  return diff === 0;
}
