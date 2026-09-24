// test/wordlist.test.ts
// Wordlist fuzzer: entry sanitization, profile bounds, and the scope gate that
// must stop every request before it leaves the Worker.

import { describe, it, expect } from "vitest";
import { sanitizeWordlistEntry, FUZZ_PROFILE, runFuzzChunk } from "../src/modules/wordlist.js";
import { compileScope } from "../src/scope/index.js";
import type { Env } from "../src/env.js";
import type { Target, ScopeEntry } from "../src/types.js";

function makeTarget(): Target {
  return {
    id: "TGT_test",
    organization_id: "default",
    name: "acme-corp.com",
    passive_only: true,
    low_impact_active: false,
    intrusive_enabled: false,
    max_request_rate_per_min: 60,
    max_concurrent_jobs: 1,
    program_rules_url: null,
    authorization_reference: "public-program",
    authorization_expires_at: "9999-12-31T23:59:59.000Z",
    paused: false,
    created_at: "2024-01-01T00:00:00Z",
  };
}

function allowOtherDomain(): ScopeEntry[] {
  return [
    {
      id: "s1", organization_id: "default", target_id: "TGT_test",
      type: "domain", value: "other.com", included: true,
      notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false,
    },
  ];
}

describe("wordlist sanitization", () => {
  it("rejects empty lines and comments", () => {
    expect(sanitizeWordlistEntry("")).toBeNull();
    expect(sanitizeWordlistEntry("  ")).toBeNull();
    expect(sanitizeWordlistEntry("# comment")).toBeNull();
  });

  it("rejects path traversal", () => {
    expect(sanitizeWordlistEntry("../etc/passwd")).toBeNull();
    expect(sanitizeWordlistEntry("..%2f..%2fetc")).toBeNull();
  });

  it("rejects NUL bytes and control chars", () => {
    expect(sanitizeWordlistEntry("admin\0")).toBeNull();
    // Trailing \r/\n are stripped by trim() like any other line ending…
    expect(sanitizeWordlistEntry("admin\r")).toBe("admin");
    expect(sanitizeWordlistEntry("admin\n")).toBe("admin");
    // …but control chars INSIDE an entry are rejected.
    expect(sanitizeWordlistEntry("ad\rmin")).toBeNull();
    expect(sanitizeWordlistEntry("ad\nmin")).toBeNull();
  });

  it("accepts reasonable paths", () => {
    expect(sanitizeWordlistEntry("admin")).toBe("admin");
    expect(sanitizeWordlistEntry("/api/v1/users")).toBe("/api/v1/users");
    expect(sanitizeWordlistEntry(".well-known/security.txt")).toBe(".well-known/security.txt");
    expect(sanitizeWordlistEntry(".env")).toBe(".env");
  });

  it("rejects over-long entries", () => {
    expect(sanitizeWordlistEntry("a".repeat(300))).toBeNull();
  });

  it("rejects shell metacharacters", () => {
    expect(sanitizeWordlistEntry("admin; rm -rf /")).toBeNull();
    expect(sanitizeWordlistEntry("admin`whoami`")).toBeNull();
    expect(sanitizeWordlistEntry("admin|whoami")).toBeNull();
    expect(sanitizeWordlistEntry("admin<redirect")).toBeNull();
  });
});

describe("fuzz profile", () => {
  it("stays inside free-tier request budgets", () => {
    expect(FUZZ_PROFILE.maxConcurrency).toBeLessThanOrEqual(2);
    expect(FUZZ_PROFILE.delayMs).toBeGreaterThanOrEqual(100);
    expect(FUZZ_PROFILE.stopOn429).toBe(true);
  });

  it("covers the four bundled wordlists", () => {
    expect(FUZZ_PROFILE.categories).toEqual(["api", "directories", "files", "fuzz"]);
  });
});

describe("runFuzzChunk", () => {
  it("never issues a request for a host outside the target scope", async () => {
    const env = { USER_AGENT: "Watchtower/test" } as unknown as Env;
    // The target scope only allows other.com → api.acme-corp.com is denied.
    const scope = compileScope(makeTarget(), allowOtherDomain());

    const result = await runFuzzChunk(
      env, "https://api.acme-corp.com/", "TGT_test", scope, 0,
      { ...FUZZ_PROFILE, maxRequests: 5 },
    );

    expect(result.results).toHaveLength(0);
    expect(result.alerts).toHaveLength(0);
    // The cursor still advances so the next tick moves on.
    expect(result.newOffset).toBe(5);
    expect(result.done).toBe(false);
  });

  it("starts from the caller's cursor", async () => {
    const env = { USER_AGENT: "Watchtower/test" } as unknown as Env;
    const scope = compileScope(makeTarget(), allowOtherDomain());

    const result = await runFuzzChunk(
      env, "https://api.acme-corp.com/", "TGT_test", scope, 42,
      { ...FUZZ_PROFILE, maxRequests: 3 },
    );

    expect(result.newOffset).toBe(45);
  });
});
