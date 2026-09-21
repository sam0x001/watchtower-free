// test/redaction-v2.test.ts
// Validates the v2 redaction module — salted fingerprints, header redaction,
// integrity verification.

import { describe, it, expect } from "vitest";
import {
  redactString,
  redactDeep,
  redactHeaders,
  scanForSecrets,
  fingerprintSecret,
  verifyIntegrity,
  REDACTED,
  isSensitiveKey,
  isSensitiveHeader,
} from "../src/lib/redact.js";

const SALT = "test-salt-do-not-use-in-prod";

describe("v2 salted secret fingerprints", () => {
  it("produces different fingerprints for different salts", async () => {
    const fp1 = await fingerprintSecret("AKIAIOSFODNN7EXAMPLE", "salt1");
    const fp2 = await fingerprintSecret("AKIAIOSFODNN7EXAMPLE", "salt2");
    expect(fp1).not.toBe(fp2);
  });

  it("produces stable fingerprints for the same salt+value", async () => {
    const fp1 = await fingerprintSecret("AKIAIOSFODNN7EXAMPLE", SALT);
    const fp2 = await fingerprintSecret("AKIAIOSFODNN7EXAMPLE", SALT);
    expect(fp1).toBe(fp2);
  });

  it("scanForSecrets never returns the full secret value", async () => {
    const text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
    const candidates = await scanForSecrets(text, { salt: SALT });
    expect(candidates.length).toBeGreaterThan(0);
    for (const c of candidates) {
      // preview is at most PREVIEW_CHARS (4) + mask
      expect(c.preview.length).toBeLessThan(20);
      expect(c.preview).not.toContain("IOSFODNN7EXAMPLE");
      // fingerprint is a hex hash, never the value
      expect(c.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("scanForSecrets dedupes by fingerprint", async () => {
    const text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE";
    const candidates = await scanForSecrets(text, { salt: SALT });
    expect(candidates).toHaveLength(1);
  });

  it("scanForSecrets respects maxCandidates ceiling", async () => {
    const text = Array.from({ length: 50 }, () => "AKIAIOSFODNN7EXAMPLE").join(" ");
    const candidates = await scanForSecrets(text, { salt: SALT, maxCandidates: 5 });
    expect(candidates.length).toBeLessThanOrEqual(5);
  });

  it("scanForSecrets throws when salt is empty (fail-closed)", async () => {
    await expect(scanForSecrets("AKIAIOSFODNN7EXAMPLE", { salt: "" })).rejects.toThrow();
  });
});

describe("redactString", () => {
  it("replaces AWS access keys", () => {
    const out = redactString("key=AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).toContain(REDACTED);
  });

  it("replaces GitHub tokens", () => {
    const out = redactString("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz0123");
    expect(out).not.toContain("ghp_0123456789abcdefghijklmnopqrstuvwxyz0123");
  });

  it("replaces Slack tokens and webhooks", () => {
    const out = redactString("SLACK=https://hooks.slack.com/services/T0AAAAAAA/B0AAAAAAA/abcdef1234567890abcdef");
    expect(out).not.toContain("abcdef1234567890abcdef");
  });

  it("replaces private key blocks", () => {
    const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    const out = redactString(text);
    expect(out).toContain(REDACTED);
    expect(out).not.toContain("MIIEpAIBAAKCAQEA");
  });
});

describe("redactDeep", () => {
  it("redacts values under sensitive keys", () => {
    const out = redactDeep({ password: "supersecret123", name: "alice" }) as Record<string, unknown>;
    expect(out["password"]).toBe(REDACTED);
    expect(out["name"]).toBe("alice");
  });

  it("scrubs strings nested in arrays", () => {
    const out = redactDeep({ tokens: ["ghp_0123456789abcdefghijklmnopqrstuvwxyz0123", "ok"] }) as Record<string, unknown>;
    const arr = out["tokens"] as unknown[];
    expect(arr[0]).toBe(REDACTED);
    expect(arr[1]).toBe("ok");
  });

  it("depth-bounds cyclic structures", () => {
    const obj: Record<string, unknown> = {};
    obj["self"] = obj;
    const out = redactDeep(obj) as Record<string, unknown>;
    expect(out["self"]).toBe("[DEPTH_LIMIT]");
  });

  it("summarises ArrayBuffer / typed arrays instead of dumping bytes", () => {
    const buf = new ArrayBuffer(64);
    const out = redactDeep(buf) as string;
    expect(out).toContain("BINARY");
    expect(out).toContain("64");
  });
});

describe("redactHeaders", () => {
  it("redacts Authorization and Cookie headers", () => {
    const out = redactHeaders({
      authorization: "Bearer eyJ...",
      cookie: "session=abc",
      "content-type": "application/json",
    });
    expect(out["authorization"]).toBe(REDACTED);
    expect(out["cookie"]).toBe(REDACTED);
    expect(out["content-type"]).toBe("application/json");
  });

  it("handles Headers object", () => {
    const h = new Headers();
    h.set("Authorization", "Bearer xxx");
    h.set("X-Forwarded-For", "1.2.3.4");
    const out = redactHeaders(h);
    expect(out["authorization"]).toBe(REDACTED);
    expect(out["x-forwarded-for"]).toBe("1.2.3.4");
  });
});

describe("verifyIntegrity", () => {
  it("returns true when hash matches", async () => {
    const content = "hello world";
    const hash = await verifyIntegrity(content, await (await import("../src/lib/redact.js")).sha256Hex(content));
    expect(hash).toBe(true);
  });

  it("returns false when hash mismatches", async () => {
    const hash = await verifyIntegrity("hello world", "0000000000000000000000000000000000000000000000000000000000000000");
    expect(hash).toBe(false);
  });
});

describe("sensitive key/header predicates", () => {
  it("isSensitiveKey matches common credential keys", () => {
    expect(isSensitiveKey("password")).toBe(true);
    expect(isSensitiveKey("api_key")).toBe(true);
    expect(isSensitiveKey("API-KEY")).toBe(true);
    expect(isSensitiveKey("access_token")).toBe(true);
    expect(isSensitiveKey("client_secret")).toBe(true);
    expect(isSensitiveKey("username")).toBe(false);
  });

  it("isSensitiveHeader matches auth-related header names", () => {
    expect(isSensitiveHeader("Authorization")).toBe(true);
    expect(isSensitiveHeader("Cookie")).toBe(true);
    expect(isSensitiveHeader("X-API-Key")).toBe(true);
    expect(isSensitiveHeader("Content-Type")).toBe(false);
  });
});
