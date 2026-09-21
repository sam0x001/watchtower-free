// test/ip.test.ts
import { describe, it, expect } from "vitest";
import { parseIPv4, parseIPv6, parseCIDR, cidrContains, isPrivateOrReserved } from "../src/utils/ip.js";

describe("IP parsing", () => {
  it("parses IPv4", () => {
    const ip = parseIPv4("192.168.1.1");
    expect(ip).not.toBeNull();
    expect(ip!.family).toBe(4);
    expect(ip!.parts).toEqual([192, 168, 1, 1]);
  });

  it("rejects invalid IPv4 octets", () => {
    expect(parseIPv4("256.1.1.1")).toBeNull();
    expect(parseIPv4("1.2.3")).toBeNull();
    expect(parseIPv4("1.2.3.4.5")).toBeNull();
  });

  it("parses IPv6 with ::", () => {
    const ip = parseIPv6("2001:db8::1");
    expect(ip).not.toBeNull();
    expect(ip!.family).toBe(6);
    expect(ip!.parts).toHaveLength(8);
  });

  it("parses full IPv6", () => {
    const ip = parseIPv6("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(ip).not.toBeNull();
  });

  it("parses IPv4-mapped IPv6", () => {
    const ip = parseIPv6("::ffff:192.168.1.1");
    expect(ip).not.toBeNull();
  });

  it("parses CIDR", () => {
    expect(parseCIDR("10.0.0.0/8")).not.toBeNull();
    expect(parseCIDR("10.0.0.0/33")).toBeNull();
    expect(parseCIDR("not-a-cidr")).toBeNull();
  });

  it("matches CIDR containment", () => {
    const cidr = parseCIDR("10.0.0.0/8")!;
    expect(cidrContains(cidr, parseIPv4("10.5.5.5")!)).toBe(true);
    expect(cidrContains(cidr, parseIPv4("11.0.0.1")!)).toBe(false);
  });

  it("detects private/reserved addresses", () => {
    expect(isPrivateOrReserved(parseIPv4("10.0.0.1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv4("192.168.1.1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv4("127.0.0.1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv4("169.254.169.254")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv4("172.16.0.1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv4("8.8.8.8")!)).toBe(false);
    expect(isPrivateOrReserved(parseIPv6("::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv6("fc00::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv6("fe80::1")!)).toBe(true);
    expect(isPrivateOrReserved(parseIPv6("2606:4700:4700::1111")!)).toBe(false);
  });
});
