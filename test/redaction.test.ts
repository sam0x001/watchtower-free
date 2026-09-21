// test/redaction.test.ts
// Backwards-compat redaction tests — adapted for v2 salted fingerprints.
// The legacy `redactSync` shim now returns redacted previews instead of
// full secret values, which is a security improvement.

import { describe, it, expect } from "vitest";
import { detectSecrets, redactSync, containsLikelySecret } from "../src/security/redaction.js";

describe("secret redaction (v2 compat)", () => {
  it("detects AWS access key IDs", async () => {
    const text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.length).toBeGreaterThan(0);
    expect(secrets[0]!.type).toBe("aws_access_key_id");
  });

  it("detects GitHub tokens", async () => {
    const text = "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz0123";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.length).toBeGreaterThan(0);
    expect(secrets.some((s) => s.type === "github_token")).toBe(true);
  });

  it("detects JWTs", async () => {
    const text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.length).toBeGreaterThan(0);
  });

  it("detects private keys", async () => {
    const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.some((s) => s.type === "private_key_block")).toBe(true);
  });

  it("redacts secrets from text", () => {
    const text = "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz0123 and password=supersecretvalue";
    const { redacted, secrets } = redactSync(text);
    expect(secrets.length).toBeGreaterThan(0);
    expect(redacted).not.toContain("ghp_0123456789abcdefghijklmnopqrstuvwxyz0123");
    expect(redacted).toContain("[REDACTED]");
  });

  it("containsLikelySecret is true for input with secrets", () => {
    expect(containsLikelySecret("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(containsLikelySecret("hello world")).toBe(false);
  });

  it("detects Slack tokens", async () => {
    const text = "SLACK_TOKEN=xoxb-1234567890-1234567890-abcdefghij1234567890abcdef";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.some((s) => s.type === "slack_token")).toBe(true);
  });

  it("detects Google API keys", async () => {
    const text = "API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.some((s) => s.type === "google_api_key")).toBe(true);
  });

  it("detects webhook URLs with secrets", async () => {
    const text = "https://hooks.slack.com/services/T0AAAAAAA/B0AAAAAAA/abcdef1234567890abcdef";
    const secrets = await detectSecrets(text, "test-salt");
    expect(secrets.some((s) => s.type === "slack_webhook")).toBe(true);
  });

  it("v2 shim never returns the full secret value", async () => {
    const text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
    const secrets = await detectSecrets(text, "test-salt");
    for (const s of secrets) {
      // The `value` field is the redacted preview, never the full secret.
      expect(s.value).not.toContain("IOSFODNN7EXAMPLE");
      expect(s.value.length).toBeLessThan(20);
    }
  });
});
