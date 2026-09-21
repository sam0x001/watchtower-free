// test/domain.test.ts
import { describe, it, expect } from "vitest";
import { normalizeDomain, isSubdomainOf, parentDomain, hostMatchesPattern } from "../src/utils/domain.js";

describe("domain normalization", () => {
  it("lowercases and strips wildcards/schemes", () => {
    expect(normalizeDomain("HTTPS://API.Example.com/path")).toBe("api.example.com");
    expect(normalizeDomain("*.example.com")).toBe("example.com");
    expect(normalizeDomain("  Example.com  ")).toBe("example.com");
  });

  it("rejects invalid domains", () => {
    expect(normalizeDomain("")).toBeNull();
    expect(normalizeDomain("..")).toBeNull();
    expect(normalizeDomain("-leading.com")).toBeNull();
    expect(normalizeDomain("trailing-.com")).toBeNull();
  });

  it("detects subdomain relationships", () => {
    expect(isSubdomainOf("api.example.com", "example.com")).toBe(true);
    expect(isSubdomainOf("v2.api.example.com", "example.com")).toBe(true);
    expect(isSubdomainOf("example.com", "example.com")).toBe(true);
    expect(isSubdomainOf("notexample.com", "example.com")).toBe(false);
    expect(isSubdomainOf("attacker.com", "example.com")).toBe(false);
  });

  it("computes parent domain", () => {
    expect(parentDomain("api.example.com")).toBe("example.com");
    expect(parentDomain("example.com")).toBe("example.com");
  });

  it("matches wildcard patterns", () => {
    expect(hostMatchesPattern("api.example.com", "*.example.com")).toBe(true);
    expect(hostMatchesPattern("example.com", "*.example.com")).toBe(true);
    expect(hostMatchesPattern("attacker.com", "*.example.com")).toBe(false);
    expect(hostMatchesPattern("api.example.com", "api.example.com")).toBe(true);
    expect(hostMatchesPattern("api.example.com", "*")).toBe(true);
  });
});
