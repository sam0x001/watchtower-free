// test/wordlist.test.ts
import { describe, it, expect } from "vitest";
import { sanitizeWordlistEntry, WORDLIST_PROFILES } from "../src/modules/wordlist.js";

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
    expect(sanitizeWordlistEntry("admin\r")).toBeNull();
    expect(sanitizeWordlistEntry("admin\n")).toBeNull();
  });

  it("accepts reasonable paths", () => {
    expect(sanitizeWordlistEntry("admin")).toBe("admin");
    expect(sanitizeWordlistEntry("/api/v1/users")).toBe("/api/v1/users");
    expect(sanitizeWordlistEntry(".well-known/security.txt")).toBe(".well-known/security.txt");
  });

  it("rejects over-long entries", () => {
    expect(sanitizeWordlistEntry("a".repeat(300))).toBeNull();
  });

  it("rejects shell metacharacters", () => {
    expect(sanitizeWordlistEntry("admin;rm -rf /")).toBeNull();
    expect(sanitizeWordlistEntry("admin`whoami`")).toBeNull();
    expect(sanitizeWordlistEntry("admin$HOME")).toBeNull();
  });
});

describe("wordlist profiles", () => {
  it("passive-only profile has zero requests", () => {
    expect(WORDLIST_PROFILES["passive-only"].maxRequests).toBe(0);
  });

  it("low-impact profiles require human approval", () => {
    expect(WORDLIST_PROFILES["low-impact-web-content"].requiresHumanApproval).toBe(true);
    expect(WORDLIST_PROFILES["low-impact-api-discovery"].requiresHumanApproval).toBe(true);
  });

  it("javascript-monitoring allows reasonable concurrency", () => {
    expect(WORDLIST_PROFILES["javascript-monitoring"].maxConcurrency).toBeLessThanOrEqual(3);
  });

  it("all profiles have stop conditions defined", () => {
    for (const profile of Object.values(WORDLIST_PROFILES)) {
      expect(Array.isArray(profile.stopConditions)).toBe(true);
    }
  });
});
