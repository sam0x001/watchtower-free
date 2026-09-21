// src/crypto/encryption.ts
// AES-GCM at-rest encryption for sensitive evidence and credentials.
// Key is provided via ENCRYPTION_KEY (base64 32 bytes), shared by the Worker.

const enc = new TextEncoder();
const dec = new TextDecoder();

interface EncryptedBlob {
  iv: string;       // base64
  ciphertext: string; // base64
  at: string;       // ISO timestamp
}

let cachedKey: CryptoKey | null = null;
let cachedKeyMaterial: string | null = null;

async function getKey(material: string): Promise<CryptoKey> {
  if (cachedKey && cachedKeyMaterial === material) return cachedKey;
  // Accept either "base64:..." or raw base64.
  const raw = material.startsWith("base64:") ? material.slice(7) : material;
  const keyBytes = base64ToBytes(raw);
  if (keyBytes.length !== 32) {
    throw new Error(`ENCRYPTION_KEY must be 32 bytes (got ${keyBytes.length})`);
  }
  cachedKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  cachedKeyMaterial = material;
  return cachedKey;
}

export async function encryptString(plaintext: string, keyMaterial: string): Promise<string> {
  const key = await getKey(keyMaterial);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );
  const blob: EncryptedBlob = {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ct)),
    at: new Date().toISOString(),
  };
  return JSON.stringify(blob);
}

export async function decryptString(serialized: string, keyMaterial: string): Promise<string> {
  const key = await getKey(keyMaterial);
  const blob = JSON.parse(serialized) as EncryptedBlob;
  const iv = base64ToBytes(blob.iv);
  const ct = base64ToBytes(blob.ciphertext);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

/**
 * Returns a short deterministic fingerprint of a secret value. The full value
 * is never stored in plaintext — only the encrypted blob (kept in evidence) and
 * this fingerprint (used for deduplication).
 */
export async function secretFingerprint(value: string): Promise<string> {
  const data = enc.encode(value.trim());
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `fp:${hex.slice(0, 16)}`;
}
