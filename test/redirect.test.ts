// test/redirect.test.ts
import { describe, it, expect } from "vitest";
import { validateRedirect } from "../src/security/redirect.js";
import { compileScope } from "../src/security/scope.js";
import type { Target, ScopeEntry } from "../src/types.js";

function makeTarget(): Target {
  return {
    id: "TGT_test", organization_id: "ORG", name: "example.com",
    passive_only: true, low_impact_active: false, intrusive_enabled: false,
    max_request_rate_per_min: 60, max_concurrent_jobs: 3, program_rules_url: null,
    authorization_reference: "X", authorization_expires_at: "2099-01-01T00:00:00Z",
    paused: false, created_at: "2024-01-01T00:00:00Z",
  };
}

const entries: ScopeEntry[] = [
  { id: "s1", organization_id: "ORG_test", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
];

describe("redirect validation", () => {
  it("allows in-scope absolute redirects", () => {
    const scope = compileScope(makeTarget(), entries);
    const result = validateRedirect("https://api.example.com/v1", "https://api.example.com/v2", scope);
    expect(result.allowed).toBe(true);
  });

  it("allows relative redirects to in-scope hosts", () => {
    const scope = compileScope(makeTarget(), entries);
    const result = validateRedirect("https://api.example.com/v1", "/v2/dashboard", scope);
    expect(result.allowed).toBe(true);
    expect(result.finalUrl).toBe("https://api.example.com/v2/dashboard");
  });

  it("rejects out-of-scope redirects", () => {
    const scope = compileScope(makeTarget(), entries);
    const result = validateRedirect("https://api.example.com/v1", "https://attacker.com/steal", scope);
    expect(result.allowed).toBe(false);
  });

  it("rejects protocol-relative redirects to attacker hosts", () => {
    const scope = compileScope(makeTarget(), entries);
    const result = validateRedirect("https://api.example.com/v1", "//attacker.com/path", scope);
    expect(result.allowed).toBe(false);
  });

  it("rejects empty redirects", () => {
    const scope = compileScope(makeTarget(), entries);
    const result = validateRedirect("https://api.example.com/v1", "", scope);
    expect(result.allowed).toBe(false);
  });
});
