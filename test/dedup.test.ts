// test/dedup.test.ts
import { describe, it, expect } from "vitest";
import { fingerprintFinding } from "../src/modules/dedup.js";

describe("finding deduplication", () => {
  it("produces a stable fingerprint", async () => {
    const f1 = { type: "exposed_secret", affected_url: "https://api.example.com/admin", detection_source: "js", cve: null, cwe: null };
    const f2 = { type: "exposed_secret", affected_url: "https://api.example.com/admin", detection_source: "js", cve: null, cwe: null };
    const a = await fingerprintFinding(f1);
    const b = await fingerprintFinding(f2);
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it("produces different fingerprints for different hosts", async () => {
    const f1 = { type: "xss", affected_url: "https://api.example.com/", detection_source: "nuclei", cve: null, cwe: "CWE-79" };
    const f2 = { type: "xss", affected_url: "https://api.attacker.com/", detection_source: "nuclei", cve: null, cwe: "CWE-79" };
    const a = await fingerprintFinding(f1);
    const b = await fingerprintFinding(f2);
    expect(a.fingerprint).not.toBe(b.fingerprint);
  });

  it("includes cve/cwe in fingerprint components", async () => {
    const f1 = { type: "cve", affected_url: null, detection_source: "osv", cve: "CVE-2024-1234", cwe: "CWE-79" };
    const fp = await fingerprintFinding(f1);
    expect(fp.components.cve).toBe("CVE-2024-1234");
    expect(fp.components.cwe).toBe("CWE-79");
  });
});
