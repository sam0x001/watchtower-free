// test/url.test.ts
import { describe, it, expect } from "vitest";
import { parseUrl, canonicalizeUrl } from "../src/utils/url.js";

describe("URL parsing", () => {
  it("parses https URLs", () => {
    const u = parseUrl("https://api.example.com/v1/users?id=42");
    expect(u).not.toBeNull();
    expect(u!.scheme).toBe("https:");
    expect(u!.host).toBe("api.example.com");
    expect(u!.port).toBe(443);
  });

  it("parses http URLs", () => {
    const u = parseUrl("http://localhost:8080/foo");
    expect(u).not.toBeNull();
    expect(u!.scheme).toBe("http:");
    expect(u!.port).toBe(8080);
  });

  it("accepts bare hosts and assumes https", () => {
    const u = parseUrl("example.com");
    expect(u).not.toBeNull();
    expect(u!.scheme).toBe("https:");
  });

  it("rejects non-http schemes", () => {
    expect(parseUrl("file:///etc/passwd")).toBeNull();
    expect(parseUrl("javascript:alert(1)")).toBeNull();
    expect(parseUrl("ftp://example.com/")).toBeNull();
  });

  it("canonicalizes URLs", () => {
    expect(canonicalizeUrl("https://example.com:443/")).toBe("https://example.com/");
    expect(canonicalizeUrl("https://example.com/v1/users/")).toBe("https://example.com/v1/users");
  });
});
