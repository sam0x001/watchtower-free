// src/utils/ip.ts
// IPv4/IPv6 parsing, CIDR matching, and SSRF-safe classification.

export interface ParsedIPv4 {
  family: 4;
  parts: [number, number, number, number];
  num: number;
}

export interface ParsedIPv6 {
  family: 6;
  parts: bigint[]; // up to 8 16-bit chunks
  expanded: string;
}

export type ParsedIP = ParsedIPv4 | ParsedIPv6;

export function parseIPv4(s: string): ParsedIPv4 | null {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = [m[1]!, m[2]!, m[3]!, m[4]!].map((n) => Number(n)) as [
    number,
    number,
    number,
    number,
  ];
  if (parts.some((p) => p < 0 || p > 255)) return null;
  const num = (parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!;
  return { family: 4, parts, num: num >>> 0 };
}

export function parseIPv6(s: string): ParsedIPv6 | null {
  const v = s.trim();
  if (!v) return null;
  // No zone IDs
  if (v.includes("%")) return null;

  // Split on "::" once
  const doubleColon = v.indexOf("::");
  let head: string[];
  let tail: string[] = [];
  let usedEllipsis = false;
  if (doubleColon >= 0) {
    const before = v.slice(0, doubleColon);
    const after = v.slice(doubleColon + 2);
    head = before ? before.split(":") : [];
    tail = after ? after.split(":") : [];
    usedEllipsis = true;
    if (after.includes("::") || before.includes("::")) return null;
  } else {
    head = v.split(":");
    if (head.length !== 8) return null;
  }

  // Handle IPv4-mapped tail like "::ffff:1.2.3.4" — the dotted quad becomes TWO
  // 16-bit segments, not one colon-joined string.
  if (tail.length > 0 && tail[tail.length - 1]!.includes(".")) {
    const v4 = parseIPv4(tail[tail.length - 1]!);
    if (!v4) return null;
    tail.splice(
      tail.length - 1,
      1,
      (v4.parts[0]! << 8 | v4.parts[1]!).toString(16),
      (v4.parts[2]! << 8 | v4.parts[3]!).toString(16),
    );
  }
  if (head.length > 0 && head[head.length - 1]!.includes(".")) {
    const v4 = parseIPv4(head[head.length - 1]!);
    if (!v4) return null;
    head.splice(
      head.length - 1,
      1,
      (v4.parts[0]! << 8 | v4.parts[1]!).toString(16),
      (v4.parts[2]! << 8 | v4.parts[3]!).toString(16),
    );
  }

  const all = [...head, ...tail];
  if (all.some((seg) => seg === "")) return null;
  if (all.some((seg) => !/^[0-9a-fA-F]{1,4}$/.test(seg))) return null;

  const totalSegments = all.length;
  if (totalSegments > 8) return null;
  if (totalSegments < 8 && !usedEllipsis) return null;

  const segments: bigint[] = [];
  for (const seg of all) {
    const v = BigInt(parseInt(seg, 16));
    segments.push(v);
  }
  while (segments.length < 8) {
    segments.splice(head.length, 0, 0n);
  }

  const expanded = segments.map((s) => s.toString(16)).join(":");
  return { family: 6, parts: segments, expanded };
}

export function parseIP(s: string): ParsedIP | null {
  return parseIPv4(s) ?? parseIPv6(s);
}

export function ipToString(ip: ParsedIP): string {
  if (ip.family === 4) return ip.parts.join(".");
  return ip.parts.map((p) => p.toString(16)).join(":");
}

export function ipv4ToBigInt(ip: ParsedIPv4): bigint {
  return BigInt(ip.num);
}

export function ipv6ToBigInt(ip: ParsedIPv6): bigint {
  let v = 0n;
  for (const p of ip.parts) {
    v = (v << 16n) | (p & 0xffffn);
  }
  return v;
}

export function ipToBigInt(ip: ParsedIP): bigint {
  return ip.family === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
}

export function parseCIDR(cidr: string): { ip: ParsedIP; prefix: number } | null {
  const idx = cidr.indexOf("/");
  if (idx < 0) return null;
  const ipPart = cidr.slice(0, idx);
  const prefixPart = cidr.slice(idx + 1);
  const prefix = Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0) return null;
  const ip = parseIP(ipPart);
  if (!ip) return null;
  const max = ip.family === 4 ? 32 : 128;
  if (prefix > max) return null;
  return { ip, prefix };
}

export function cidrContains(cidr: { ip: ParsedIP; prefix: number }, candidate: ParsedIP): boolean {
  if (cidr.ip.family !== candidate.family) return false;
  const max = cidr.ip.family === 4 ? 32 : 128;
  const shift = BigInt(max - cidr.prefix);
  const mask = shift >= 128n ? 0n : ((1n << BigInt(cidr.prefix)) - 1n) << shift;
  return (ipToBigInt(cidr.ip) & mask) === (ipToBigInt(candidate) & mask);
}

export function isIPv4MappedIPv6(ip: ParsedIPv6): boolean {
  if (ip.parts.length !== 8) return false;
  return (
    ip.parts[0]! === 0n && ip.parts[1]! === 0n && ip.parts[2]! === 0n &&
    ip.parts[3]! === 0n && ip.parts[4]! === 0n && ip.parts[5]! === 0xffffn
  );
}

/** Is `ip` inside any blocked/private/reserved/metadata range? */
export function isPrivateOrReserved(ip: ParsedIP): boolean {
  if (ip.family === 4) {
    const n = ip.num;
    // NOTE: JS bitwise ops return SIGNED 32-bit ints, so every masked value must
    // be coerced back to unsigned before comparing with a constant >= 0x80000000
    // (192.168/16, 169.254/16, 172.16/12, 224/4 …). Without `>>> 0` those ranges
    // silently fell through as "public".
    const masked = (mask: number): number => (n & mask) >>> 0;
    if (masked(0xff000000) === 0x0a000000) return true;  // 10/8
    if (masked(0xffc00000) === 0x64400000) return true;  // 100.64/10 CGNAT
    if (masked(0xff000000) === 0x7f000000) return true;  // 127/8
    if (masked(0xffff0000) === 0xa9fe0000) return true;  // 169.254/16
    if (masked(0xfff00000) === 0xac100000) return true;  // 172.16/12
    if (masked(0xffffff00) === 0xc0000000) return true;  // 192.0.0/24
    if (masked(0xffffff00) === 0xc0000200) return true;  // 192.0.2/24
    if (masked(0xffff0000) === 0xc0a80000) return true;  // 192.168/16
    if (masked(0xfffe0000) === 0xc6120000) return true;  // 198.18/15
    if (masked(0xffffff00) === 0xc6336400) return true;  // 198.51.100/24
    if (masked(0xffffff00) === 0xcb007100) return true;  // 203.0.113/24
    if (masked(0xf0000000) === 0xe0000000) return true;  // 224/4 multicast
    if (masked(0xf0000000) === 0xf0000000) return true;  // 240/4 reserved
    if (n === 0xffffffff) return true;                   // broadcast
    if (n === 0) return true;                            // 0.0.0.0
    return false;
  }
  if (ip.parts.length !== 8) return false;
  // ::1 loopback
  if (ip.parts.every((p, i) => (i === 7 ? p === 1n : p === 0n))) return true;
  // :: unspecified
  if (ip.parts.every((p) => p === 0n)) return true;
  // IPv4-mapped
  if (isIPv4MappedIPv6(ip)) {
    const v4: ParsedIPv4 = {
      family: 4,
      parts: [
        Number((ip.parts[6]! >> 8n) & 0xffn),
        Number(ip.parts[6]! & 0xffn),
        Number((ip.parts[7]! >> 8n) & 0xffn),
        Number(ip.parts[7]! & 0xffn),
      ],
      num:
        (Number((ip.parts[6]! >> 8n) & 0xffn) << 24) |
        (Number(ip.parts[6]! & 0xffn) << 16) |
        (Number((ip.parts[7]! >> 8n) & 0xffn) << 8) |
        Number(ip.parts[7]! & 0xffn),
    };
    return isPrivateOrReserved(v4);
  }
  // fc00::/7 ULA
  if ((ip.parts[0]! & 0xfe00n) === 0xfc00n) return true;
  // fe80::/10 link-local
  if ((ip.parts[0]! & 0xffc0n) === 0xfe80n) return true;
  // ff00::/8 multicast
  if ((ip.parts[0]! & 0xff00n) === 0xff00n) return true;
  // 2001:db8::/32 documentation
  if (ip.parts[0]! === 0x2001n && ip.parts[1]! === 0x0db8n) return true;
  return false;
}
