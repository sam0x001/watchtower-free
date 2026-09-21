// test/scope.test.ts
import { describe, it, expect } from "vitest";
import {
  compileScope,
  checkHostInScope,
  checkUrlInScope,
  isWildcardTooBroad,
} from "../src/security/scope.js";
import type { Target, ScopeEntry } from "../src/types.js";

function makeTarget(overrides: Partial<Target> = {}): Target {
  return {
    id: "TGT_test",
    organization_id: "ORG_test",
    name: "example.com",
    passive_only: true,
    low_impact_active: false,
    intrusive_enabled: false,
    max_request_rate_per_min: 60,
    max_concurrent_jobs: 3,
    program_rules_url: null,
    authorization_reference: "WRITTEN-CONTRACT-001",
    authorization_expires_at: "2099-01-01T00:00:00Z",
    paused: false,
    created_at: "2024-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("scope engine", () => {
  it("allows hosts matching a wildcard domain pattern", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    expect(checkHostInScope(compiled, "api.example.com").allowed).toBe(true);
    expect(checkHostInScope(compiled, "v2.api.example.com").allowed).toBe(true);
    expect(checkHostInScope(compiled, "example.com").allowed).toBe(true);
  });

  it("rejects out-of-scope hosts", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    expect(checkHostInScope(compiled, "attacker.com").allowed).toBe(false);
  });

  it("rejects private IP ranges by default", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "cidr", value: "10.0.0.0/8", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    const result = checkHostInScope(compiled, "10.0.0.5");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("blocked_ip_range");
  });

  it("blocks cloud metadata endpoints", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    expect(checkHostInScope(compiled, "169.254.169.254").allowed).toBe(false);
    expect(checkHostInScope(compiled, "metadata.google.internal").allowed).toBe(false);
  });

  it("rejects broad wildcards", () => {
    expect(isWildcardTooBroad("*")).toBe(true);
    expect(isWildcardTooBroad("*.com")).toBe(true);
    expect(isWildcardTooBroad("*.example.com")).toBe(false);
  });

  it("denies hosts in the denylist even when matching an allowlist", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
      { id: "s2", target_id: "TGT_test", type: "domain", value: "internal.example.com", included: false, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    expect(checkHostInScope(compiled, "internal.example.com").allowed).toBe(false);
    expect(checkHostInScope(compiled, "api.example.com").allowed).toBe(true);
  });

  it("rejects when authorization has expired", () => {
    const target = makeTarget({ authorization_expires_at: "2020-01-01T00:00:00Z" });
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    const result = checkHostInScope(compiled, "api.example.com");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("URL scope check enforces host + URL prefix", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "wildcard_domain", value: "*.example.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    expect(checkUrlInScope(compiled, "https://api.example.com/v1/users").allowed).toBe(true);
    expect(checkUrlInScope(compiled, "https://attacker.com/v1/users").allowed).toBe(false);
  });

  it("handles IDN/punycode domains", () => {
    const target = makeTarget();
    const entries: ScopeEntry[] = [
      { id: "s1", target_id: "TGT_test", type: "domain", value: "xn--exmple-cua.com", included: true, notes: null, created_at: "2024-01-01T00:00:00Z", expires_at: null, paused: false },
    ];
    const compiled = compileScope(target, entries);
    // Hostname matching is exact-match; punycode must match punycode
    expect(checkHostInScope(compiled, "xn--exmple-cua.com").allowed).toBe(true);
  });

  it("returns 'no_scope' when no allowlist entries exist", () => {
    const target = makeTarget();
    const compiled = compileScope(target, []);
    const result = checkHostInScope(compiled, "api.example.com");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("no_scope");
  });
});
