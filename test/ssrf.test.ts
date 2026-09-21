// test/ssrf.test.ts
import { describe, it, expect } from "vitest";
import { filterBlockedIps } from "../src/security/ssrf.js";
import { parseIP } from "../src/utils/ip.js";

describe("SSRF protection", () => {
  it("blocks private IPv4 ranges", () => {
    const result = filterBlockedIps(["10.0.0.5", "127.0.0.1", "192.168.1.1", "169.254.169.254"]);
    expect(result.allowed).toBe(false);
    expect(result.ok).toHaveLength(0);
    expect(result.blocked).toHaveLength(4);
  });

  it("allows public IPs", () => {
    const result = filterBlockedIps(["93.184.216.34", "1.1.1.1"]);
    expect(result.allowed).toBe(true);
    expect(result.ok).toHaveLength(2);
  });

  it("blocks IPv6 loopback and link-local", () => {
    const result = filterBlockedIps(["::1", "fe80::1", "fc00::1"]);
    expect(result.allowed).toBe(false);
  });

  it("blocks IPv4-mapped IPv6 addresses that map to private space", () => {
    const ip = parseIP("::ffff:10.0.0.5");
    expect(ip).not.toBeNull();
    expect(result_isBlocked(ip!)).toBe(true);
  });

  it("allows public IPv6", () => {
    const result = filterBlockedIps(["2606:4700:4700::1111"]);
    expect(result.allowed).toBe(true);
  });

  it("rejects unparseable IPs as blocked", () => {
    const result = filterBlockedIps(["not-an-ip"]);
    expect(result.blocked).toContain("not-an-ip");
    expect(result.allowed).toBe(false);
  });
});

function result_isBlocked(ip: ReturnType<typeof parseIP>): boolean {
  if (!ip) return false;
  // Re-use the same logic by calling filterBlockedIps on the string form
  // (re-implemented here for clarity — for the test we just call the original)
  return filterBlockedIps([ip.family === 4 ? ip.parts.join(".") : ip.parts.map((p) => p.toString(16)).join(":")]).blocked.length > 0;
}
