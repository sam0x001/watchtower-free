// test/authorization.test.ts
import { describe, it, expect } from "vitest";
import { isScopeExpired, scopeExpiringSoon } from "../src/security/scope.js";
import type { Target } from "../src/types.js";

function makeTarget(expiresAt: string): Target {
  return {
    id: "TGT", organization_id: "ORG", name: "example.com",
    passive_only: true, low_impact_active: false, intrusive_enabled: false,
    max_request_rate_per_min: 60, max_concurrent_jobs: 3, program_rules_url: null,
    authorization_reference: "REF", authorization_expires_at: expiresAt,
    paused: false, created_at: "2024-01-01T00:00:00Z",
  };
}

describe("authorization expiration", () => {
  it("is expired when expires_at is in the past", () => {
    const t = makeTarget("2020-01-01T00:00:00Z");
    expect(isScopeExpired(t)).toBe(true);
  });

  it("is not expired when expires_at is in the future", () => {
    const t = makeTarget("2099-01-01T00:00:00Z");
    expect(isScopeExpired(t)).toBe(false);
  });

  it("warns when expiring within warningDays", () => {
    const t = makeTarget(new Date(Date.now() + 3 * 86_400_000).toISOString());
    expect(scopeExpiringSoon(t, 7)).toBe(true);
  });

  it("does not warn when expiry is far away", () => {
    const t = makeTarget("2099-01-01T00:00:00Z");
    expect(scopeExpiringSoon(t, 7)).toBe(false);
  });
});
