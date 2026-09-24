// test/scope-engine-v2.test.ts
// Validates the hardened scope engine merged from watchtower1 — control-proof
// host detection, reserved documentation domains, state-changing method
// gating, and the fail-closed loader semantics.

import { describe, it, expect } from "vitest";
import {
  evaluateScope,
  isBlockedIp,
  isWildcardTooBroad,
  type ScopeRecord,
} from "../src/scope/match.js";

function scope(overrides: Partial<ScopeRecord> = {}): ScopeRecord {
  return {
    id: "scp_test",
    organizationId: "org",
    targetId: "tgt",
    scopeType: "wildcard_domain",
    value: "*.example.com",
    label: "test",
    status: "active",
    isAllowlist: true,
    passiveOnly: false,
    lowImpactActive: true,
    intrusiveEnabled: false,
    validFrom: null,
    validUntil: null,
    ...overrides,
  };
}

describe("hardened scope engine (v2)", () => {
  it("blocks cloud metadata endpoints explicitly", () => {
    const s = [scope()];
    // AWS IMDS
    const d1 = evaluateScope("169.254.169.254", s, {});
    expect(d1.allowed).toBe(false);
    // GCP metadata
    const d2 = evaluateScope("metadata.google.internal", s, {});
    expect(d2.allowed).toBe(false);
    // Alibaba metadata
    const d3 = evaluateScope("100.100.100.200", s, {});
    expect(d3.allowed).toBe(false);
  });

  it("blocks control-proof host prefixes", () => {
    const s = [scope()];
    expect(evaluateScope("_acme-challenge.example.com", s, {}).allowed).toBe(false);
    expect(evaluateScope("_dmarc.example.com", s, {}).allowed).toBe(false);
    expect(evaluateScope("_domainkey.example.com", s, {}).allowed).toBe(false);
  });

  it("blocks reserved documentation domains", () => {
    const s = [scope({ value: "*.example.com" })];
    // example.com is RFC 2606 reserved — can never be scoped
    const d = evaluateScope("host.example.com", s, {});
    expect(d.allowed).toBe(false);
  });

  it("requires explicit allow rule for state-changing methods", () => {
    const s = [scope({ value: "*.acme-corp.com" })];
    const get = evaluateScope("https://api.acme-corp.com/v1", s, { method: "GET" });
    expect(get.allowed).toBe(true);
    const post = evaluateScope("https://api.acme-corp.com/v1", s, { method: "POST" });
    expect(post.allowed).toBe(false);
    expect(post.reason).toContain("state-changing");
  });

  it("refuses broad wildcards", () => {
    expect(isWildcardTooBroad("*")).toBe(true);
    expect(isWildcardTooBroad("*.com")).toBe(true);
    expect(isWildcardTooBroad("*.example.com")).toBe(false);
  });

  it("blocks IPv6 ULA, multicast, link-local", () => {
    expect(isBlockedIp("fc00::1")).toBe(true);
    expect(isBlockedIp("fd12:3456::1")).toBe(true);
    expect(isBlockedIp("fe80::1")).toBe(true);
    expect(isBlockedIp("ff02::1")).toBe(true);
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
  });

  it("blocks documentation IPv6 (2001:db8::)", () => {
    expect(isBlockedIp("2001:db8::1")).toBe(true);
  });

  it("blocks NAT64 64:ff9b::", () => {
    expect(isBlockedIp("64:ff9b::1")).toBe(true);
  });

  it("emergencyStop short-circuits to denial", () => {
    const s = [scope()];
    const d = evaluateScope("api.example.com", s, { emergencyStop: true });
    expect(d.allowed).toBe(false);
    expect(d.validation).toBe("denied");
  });

  it("denies when no scope exists for target", () => {
    const d = evaluateScope("api.acme-corp.com", [], {});
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain("no scope");
  });

  it("allowlist matches, denylist overrides", () => {
    const allow = scope({ value: "*.acme-corp.com" });
    const deny: ScopeRecord = scope({
      id: "scp_deny",
      value: "internal.acme-corp.com",
      isAllowlist: false,
      scopeType: "domain",
    });
    expect(evaluateScope("api.acme-corp.com", [allow, deny], {}).allowed).toBe(true);
    expect(evaluateScope("internal.acme-corp.com", [allow, deny], {}).allowed).toBe(false);
  });

  it("expired scope entries are not honored", () => {
    const s = [scope({ status: "expired", value: "*.acme-corp.com" })];
    const d = evaluateScope("api.acme-corp.com", s, {});
    expect(d.allowed).toBe(false);
    expect(d.validation).toBe("expired");
  });

  it("paused scope entries are not honored", () => {
    const s = [scope({ status: "paused", value: "*.acme-corp.com" })];
    const d = evaluateScope("api.acme-corp.com", s, {});
    expect(d.allowed).toBe(false);
  });
});
