// test/exclusions.test.ts
// /exclude argument classification: subdomain, wildcard subdomain or path.

import { describe, it, expect } from "vitest";
import { classifyExclusion } from "../src/telegram/commands.js";

describe("classifyExclusion", () => {
  it("treats a bare hostname as a domain exclusion", () => {
    expect(classifyExclusion("sub.example.com")).toEqual({ type: "domain", value: "sub.example.com" });
  });

  it("treats a *.host as a wildcard subdomain exclusion", () => {
    expect(classifyExclusion("*.dev.example.com")).toEqual({ type: "wildcard_domain", value: "*.dev.example.com" });
  });

  it("treats host/path as a URL exclusion", () => {
    expect(classifyExclusion("example.com/excluded")).toEqual({ type: "url", value: "https://example.com/excluded" });
  });

  it("accepts an explicit scheme and drops the trailing slash", () => {
    expect(classifyExclusion("https://example.com/admin/")).toEqual({ type: "url", value: "https://example.com/admin" });
  });

  it("normalizes case, whitespace and a leading www.", () => {
    expect(classifyExclusion("  API.Example.COM ")).toEqual({ type: "domain", value: "api.example.com" });
    // A host is excluded exactly as written — `www.` is a real label, not noise.
    expect(classifyExclusion("www.example.com")).toEqual({ type: "domain", value: "www.example.com" });
  });

  it("rejects junk", () => {
    expect(classifyExclusion("")).toBeNull();
    expect(classifyExclusion("https://")).toBeNull();
  });
});
