/**
 * Watchtower - scope engine.
 *
 * This module is the single gate between "an operator typed something" and
 * "a scanner touches a host". Every provider adapter, queue consumer, runner
 * job and REST handler MUST call `evaluateScope` before issuing a request.
 *
 * Design rules encoded here:
 *   1. Default deny. If nothing explicitly allows an asset, it is out of scope.
 *   2. Deny always beats allow, including for subdomains of an allowed parent.
 *   3. Reserved / documentation domains are never authorizable.
 *   4. Private, loopback, link-local, multicast, broadcast and cloud-metadata
 *      ranges are hard-blocked before any scope row is consulted.
 *   5. Wildcards must look like wildcards: `*.example.com` matches exactly one
 *      label by default.
 *   6. Proof-of-control hostname prefixes (e.g. `_acme-challenge`) never
 *      satisfy a scope.
 */

import type { ScopeDecision, ScopeStatus, ScopeType, ScanMode } from '../types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A scope rule row, as loaded from D1 (`scope_rules`). */
export interface ScopeRule {
  id: string;
  scopeId: string;
  ruleKind: 'port' | 'path' | 'method' | 'scheme' | 'asset_type' | 'header' | 'parameter' | 'host';
  effect: 'allow' | 'deny';
  value: string;
  valueEnd?: string | null;
}

/** A scope row, as loaded from D1 (`scopes`). */
export interface ScopeRecord {
  id: string;
  organizationId: string;
  targetId: string;
  scopeType: ScopeType;
  value: string;
  label: string;
  status: ScopeStatus;
  /** false means this is a denylist entry. */
  isAllowlist: boolean;
  passiveOnly: boolean;
  lowImpactActive: boolean;
  intrusiveEnabled: boolean;
  /** ISO-8601, inclusive. */
  validFrom?: string | null;
  /** ISO-8601, exclusive. */
  validUntil?: string | null;
  rules?: ScopeRule[];
}

/** A parsed asset reference: the normalized form of "something we may touch". */
export interface ParsedAsset {
  /** Lowercase, punycode-normalized hostname, or the literal IP. */
  hostname: string;
  scheme: string | null;
  port: number | null;
  path: string;
  /** Present only when the input was an IP literal. */
  ip: string | null;
  /** True when the hostname component is an IP literal. */
  isIpLiteral: boolean;
  /** True when the hostname is in a private or reserved range. */
  isPrivateOrReserved: boolean;
  /** Reason the asset is unsafe, if any. */
  unsafeReason?: string;
}

export interface EvaluateScopeOptions {
  /** Current time; injectable for deterministic tests. */
  now?: Date;
  /** Requested action mode. Passive never needs active enablement. */
  mode?: ScanMode;
  /** HTTP method, when the caller is about to issue a request. */
  method?: string;
  /** Target-level pause / expiry gate; evaluated before scope rows. */
  target?: {
    status?: string;
    authorizationStatus?: string;
    validFrom?: string | null;
    validUntil?: string | null;
    passiveOnly?: boolean;
    lowImpactActive?: boolean;
    intrusiveEnabled?: boolean;
  } | null;
  /** Organization emergency stop; short-circuits everything. */
  emergencyStop?: boolean;
}

// ---------------------------------------------------------------------------
// Blocked network ranges
// ---------------------------------------------------------------------------

/** Hostname suffixes that are never authorizable. */
const BLOCKED_HOST_SUFFIXES: readonly string[] = [
  '.localhost',
  '.local',
  '.localdomain',
  '.internal',
  '.intranet',
  '.corp',
  '.home',
  '.lan',
  '.onion',
  '.i2p',
];

/** Exact hostnames that are never authorizable. */
const BLOCKED_HOSTS: readonly string[] = [
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
];

/**
 * Cloud metadata service addresses. These are the single most attractive SSRF
 * pivot, so they are blocked by exact match rather than by range, and the
 * check runs before DNS resolution and again after it.
 */
const METADATA_ADDRESSES: readonly string[] = [
  '169.254.169.254', // AWS / Azure / GCP / OpenStack IMDS
  '169.254.169.253', // Azure wire server / DNS
  '169.254.169.123', // AWS time sync
  '169.254.170.2', // AWS ECS task metadata
  '100.100.100.200', // Alibaba Cloud
  '192.0.0.192', // Oracle Cloud
  'fd00:ec2::254', // AWS IMDSv6
  'fdaa:0:0:0:0:0:0:1', // Fly.io / IPv6 ULA metadata
  'fe80::a9fe:a9fe', // link-local IMDS form
];

/**
 * RFC 2606 / RFC 6761 reserved names used for documentation, testing and local
 * resolution. These are never authorizable because the platform must not be
 * able to point a scanner at IANA-controlled documentation space by accident.
 */
const RESERVED_DOC_SUFFIXES: readonly string[] = [
  'example.com',
  'example.net',
  'example.org',
  'example.edu',
  'test',
  'invalid',
  'example',
  'localhost',
];

/** Hostname prefixes that prove DNS control rather than asset ownership. */
const CONTROL_PROOF_PREFIXES: readonly string[] = [
  '_acme-challenge.',
  '_dmarc.',
  '_domainkey.',
  '_dkim.',
  '_spf.',
];

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+$/;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export function isIpLiteral(value: string): boolean {
  if (IPV4_RE.test(value)) {
    return value.split('.').every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  return value.includes(':') && IPV6_RE.test(value);
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  const [a = 0, b = 0, c = 0, d = 0] = parts;
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function inCidr4(ip: string, cidr: string): boolean {
  const [base = '', bitsRaw = ''] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

/**
 * True for IPv4/IPv6 addresses that must never be reached: loopback, private,
 * link-local, CGNAT, multicast, broadcast, benchmarking, documentation and
 * unspecified ranges.
 */
export function isBlockedIp(ip: string): boolean {
  const value = String(ip).trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (METADATA_ADDRESSES.includes(value)) return true;

  if (IPV4_RE.test(value)) {
    return (
      inCidr4(value, '0.0.0.0/8') || // "this network"
      inCidr4(value, '10.0.0.0/8') || // RFC1918
      inCidr4(value, '100.64.0.0/10') || // CGNAT
      inCidr4(value, '127.0.0.0/8') || // loopback
      inCidr4(value, '169.254.0.0/16') || // link-local + metadata
      inCidr4(value, '172.16.0.0/12') || // RFC1918
      inCidr4(value, '192.0.0.0/24') || // IETF protocol assignments
      inCidr4(value, '192.0.2.0/24') || // TEST-NET-1
      inCidr4(value, '192.88.99.0/24') || // 6to4 relay anycast
      inCidr4(value, '192.168.0.0/16') || // RFC1918
      inCidr4(value, '198.18.0.0/15') || // benchmarking
      inCidr4(value, '198.51.100.0/24') || // TEST-NET-2
      inCidr4(value, '203.0.113.0/24') || // TEST-NET-3
      inCidr4(value, '224.0.0.0/4') || // multicast
      inCidr4(value, '240.0.0.0/4') // reserved + broadcast
    );
  }

  if (value.includes(':')) {
    if (value === '::' || value === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(value)) return true; // fc00::/7 unique local
    if (/^fe[89ab][0-9a-f]:/.test(value)) return true; // fe80::/10 link-local
    if (/^ff[0-9a-f]{2}:/.test(value)) return true; // ff00::/8 multicast
    if (value.startsWith('2001:db8:')) return true; // documentation
    if (value.startsWith('64:ff9b:')) return true; // NAT64
    return false;
  }

  return false;
}

/** True when a literal IP is a cloud metadata endpoint. */
export function isMetadataAddress(ip: string): boolean {
  return METADATA_ADDRESSES.includes(String(ip).trim().toLowerCase().replace(/^\[|\]$/g, ''));
}

export function isReservedDocDomain(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return RESERVED_DOC_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** True for DNS-control records that do not imply asset ownership. */
export function isControlProofHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return CONTROL_PROOF_PREFIXES.some((prefix) => host.startsWith(prefix));
}

// ---------------------------------------------------------------------------
// Hostname normalization
// ---------------------------------------------------------------------------

/**
 * Normalizes a hostname for comparison: trims, lowercases, strips a single
 * trailing dot (FQDN root), converts IDN to punycode via URL, and rejects
 * anything containing characters that could confuse matching.
 *
 * Returns null when the input cannot be safely normalized; callers must treat
 * null as "deny" rather than "skip".
 */
export function normalizeHostname(input: string): string | null {
  if (typeof input !== 'string') return null;
  let host = input.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return null;

  // Strip a single trailing dot so `example.com.` == `example.com`.
  if (host.endsWith('.') && host !== '.') host = host.slice(0, -1);
  // Strip brackets from IPv6 literals.
  host = host.replace(/^\[|\]$/g, '');
  if (host.length === 0) return null;

  // Reject control characters, whitespace, and URL metacharacters that could
  // let a matcher see one thing while fetch() sees another.
  if (/[\s\u0000-\u001f\u007f]/.test(host)) return null;
  if (/[/\\?#@]/.test(host)) return null;

  if (isIpLiteral(host)) return host;

  // Punycode-convert IDN labels. URL throws on malformed input, which we
  // treat as invalid rather than passing through unnormalized.
  try {
    const url = new URL(`https://${host}`);
    const ascii = url.hostname.toLowerCase();
    if (ascii.length === 0 || ascii.length > 253) return null;
    if (!/^[a-z0-9._-]+$/.test(ascii)) return null;
    const labels = ascii.split('.');
    if (labels.some((label) => label.length === 0 || label.length > 63)) return null;
    // Bare single-label names are only meaningful with a search domain;
    // refuse them so nobody scans a NetBIOS name by accident.
    if (labels.length < 2) return null;
    return ascii;
  } catch {
    return null;
  }
}

/** Removes the leading wildcard from a scope value. */
export function stripWildcard(value: string): string {
  return value.trim().toLowerCase().replace(/^\*\./, '');
}

/**
 * True when a wildcard scope value is dangerously broad.
 *
 * `*.com`, `*.io` or `*.co.uk` would authorize an entire public suffix, which
 * is never acceptable. We reject one-label bases outright and reject a
 * curated list of multi-label public suffixes, since we cannot verify registry
 * ownership from inside the Worker.
 */
const MULTI_LABEL_PUBLIC_SUFFIXES: readonly string[] = [
  'co.uk',
  'org.uk',
  'me.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'co.jp',
  'or.jp',
  'ne.jp',
  'ac.jp',
  'com.br',
  'com.cn',
  'com.mx',
  'com.ar',
  'com.tr',
  'com.sg',
  'com.hk',
  'com.tw',
  'com.my',
  'co.in',
  'co.za',
  'co.kr',
  'co.nz',
  'co.id',
  'co.il',
  'co.th',
  'com.co',
  'com.pe',
  'com.ec',
  'com.uy',
  'com.py',
  'com.bo',
  'com.do',
  'com.gt',
  'com.ng',
  'com.gh',
  'com.pk',
  'com.sa',
  'com.ua',
  'com.vn',
];

export function isWildcardTooBroad(value: string): boolean {
  const base = stripWildcard(value);
  const labels = base.split('.').filter(Boolean);
  // `*.com`, `*.local`, `*` — a single label is never a registrable domain.
  if (labels.length < 2) return true;
  // `*.co.uk` and friends authorize a whole public suffix.
  if (labels.length === 2 && MULTI_LABEL_PUBLIC_SUFFIXES.includes(base)) return true;
  return false;
}

/** True when `host` is exactly `base` or a proper subdomain of it. */
export function isHostWithin(host: string, base: string): boolean {
  if (host === base) return true;
  // Require the dot so `evilexample.com` never matches base `example.com`.
  return host.endsWith(`.${base}`);
}

// ---------------------------------------------------------------------------
// Asset parsing
// ---------------------------------------------------------------------------

export interface ParseAssetOptions {
  /** Scheme assumed when the input has none. Default `https`. */
  defaultScheme?: string;
}

/**
 * Parses an arbitrary operator-supplied asset string into a normalized
 * reference. Never throws: a malformed input yields a record with
 * `unsafeReason` set, which `evaluateScope` converts into a denial.
 */
export function parseAsset(raw: string, options: ParseAssetOptions = {}): ParsedAsset {
  const defaultScheme = options.defaultScheme ?? 'https';
  const deny = (reason: string): ParsedAsset => ({
    hostname: '',
    scheme: null,
    port: null,
    path: '/',
    ip: null,
    isIpLiteral: false,
    isPrivateOrReserved: true,
    unsafeReason: reason,
  });

  if (typeof raw !== 'string' || raw.trim().length === 0) {
    return deny('empty asset reference');
  }
  if (raw.length > 2048) {
    return deny('asset reference exceeds 2048 characters');
  }

  const input = raw.trim();

  // Bare IPv4 CIDR is not a URL; normalize to the network base.
  if (/^[0-9.]+(\/[0-9]{1,2})?$/.test(input) && input.includes('/')) {
    const [base = '', bitsRaw = ''] = input.split('/');
    const bits = Number(bitsRaw);
    if (!IPV4_RE.test(base) || !Number.isInteger(bits) || bits < 0 || bits > 32) {
      return deny('malformed CIDR');
    }
    const safeBase = base
      .split('.')
      .map((part) => String(Math.min(255, Math.max(0, Number(part)))))
      .join('.');
    return {
      hostname: safeBase,
      scheme: null,
      port: null,
      path: '/',
      ip: safeBase,
      isIpLiteral: true,
      isPrivateOrReserved: isBlockedIp(safeBase),
    };
  }

  // Add a scheme when missing so URL() can parse bare hostnames.
  let withScheme = input;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(withScheme)) {
    withScheme = `${defaultScheme}://${withScheme}`;
  }

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return deny('unparseable asset reference');
  }

  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  if (!['http', 'https', 'ws', 'wss'].includes(scheme)) {
    return deny(`unsupported scheme "${scheme}"`);
  }
  if (url.username || url.password) {
    return deny('credentials embedded in asset reference');
  }

  const rawHost = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const normalized = normalizeHostname(rawHost);
  if (!normalized) {
    return deny('hostname failed normalization');
  }

  const literal = isIpLiteral(normalized);
  const explicitPort = url.port === '' ? null : Number(url.port);
  const port = explicitPort ?? (scheme === 'http' || scheme === 'ws' ? 80 : 443);

  // Normalize the path: collapse repeated slashes, ensure a leading slash and
  // strip a trailing slash (except root) so `/admin` and `/admin/` compare equal.
  let path = url.pathname || '/';
  path = path.replace(/\/{2,}/g, '/');
  if (!path.startsWith('/')) path = `/${path}`;
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
  // Reject encoded traversal that survives URL normalization.
  if (/%2e%2e|%252e|\.\.\//i.test(path)) {
    return deny('path traversal sequence in asset reference');
  }

  const blockedSuffix = BLOCKED_HOST_SUFFIXES.some(
    (suffix) => normalized === suffix.slice(1) || normalized.endsWith(suffix),
  );
  const reserved = isBlockedIp(normalized) || isReservedDocDomain(normalized);
  const blockedHost = BLOCKED_HOSTS.includes(normalized);

  let unsafeReason: string | undefined;
  if (literal && isMetadataAddress(normalized)) {
    unsafeReason = 'cloud metadata endpoint is never authorizable';
  } else if (isBlockedIp(normalized)) {
    unsafeReason = 'address is in a blocked private or reserved range';
  } else if (blockedHost) {
    unsafeReason = 'reserved local hostname is never authorizable';
  } else if (blockedSuffix) {
    unsafeReason = 'reserved or non-routable hostname suffix';
  }

  const result: ParsedAsset = {
    hostname: normalized,
    scheme,
    port,
    path,
    ip: literal ? normalized : null,
    isIpLiteral: literal,
    isPrivateOrReserved: reserved || blockedHost || blockedSuffix,
  };
  if (unsafeReason) result.unsafeReason = unsafeReason;
  return result;
}

// ---------------------------------------------------------------------------
// Scope record matching
// ---------------------------------------------------------------------------

/** True when a scope row is currently usable. */
export function isScopeActive(scope: ScopeRecord, now: Date): boolean {
  if (scope.status !== 'active') return false;
  if (scope.validFrom && now.getTime() < Date.parse(scope.validFrom)) return false;
  if (scope.validUntil && now.getTime() >= Date.parse(scope.validUntil)) return false;
  return true;
}

/** Normalized comparison form of a scope value. */
interface NormalizedScopeValue {
  hostname: string;
  path: string;
  isIpScope: boolean;
  isCidr: boolean;
}

/**
 * Normalizes a scope row's `value` into a comparable form. Returns null when
 * the stored value is itself unusable, in which case the scope can never
 * authorize anything (fail closed).
 */
export function normalizeScopeValue(scope: ScopeRecord): NormalizedScopeValue | null {
  const raw = scope.value.trim();
  if (raw.length === 0) return null;

  if (scope.scopeType === 'cidr') {
    const [base = '', bitsRaw = ''] = raw.split('/');
    const bits = Number(bitsRaw);
    if (!IPV4_RE.test(base) || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    return { hostname: base, path: '/', isIpScope: true, isCidr: true };
  }

  if (scope.scopeType === 'ip') {
    const host = normalizeHostname(raw);
    if (!host || !isIpLiteral(host)) return null;
    return { hostname: host, path: '/', isIpScope: true, isCidr: false };
  }

  if (scope.scopeType === 'wildcard_domain') {
    const base = stripWildcard(raw);
    if (isWildcardTooBroad(base)) return null;
    const host = normalizeHostname(base);
    if (!host) return null;
    return { hostname: host, path: '/', isIpScope: false, isCidr: false };
  }

  if (scope.scopeType === 'domain') {
    const host = normalizeHostname(stripWildcard(raw));
    if (!host) return null;
    return { hostname: host, path: '/', isIpScope: isIpLiteral(host), isCidr: false };
  }

  // url / api / repository: the value carries a path we must honour as a prefix.
  const parsed = parseAsset(raw);
  if (!parsed.hostname) return null;
  return {
    hostname: parsed.hostname,
    path: parsed.path,
    isIpScope: parsed.isIpLiteral,
    isCidr: false,
  };
}

/** True when a CIDR scope value contains the asset's IP. */
function cidrContains(cidrValue: string, ip: string): boolean {
  if (!IPV4_RE.test(ip) || !IPV4_RE.test(cidrValue.split('/')[0] ?? '')) return false;
  return inCidr4(ip, cidrValue);
}

/**
 * Tests whether a single scope row authorizes an asset's host and path.
 * Does NOT consider status, expiry or rules; those are handled by
 * `evaluateScope` so callers can distinguish "not covered" from "expired".
 */
export function assetMatchesScope(asset: ParsedAsset, scope: ScopeRecord): boolean {
  const norm = normalizeScopeValue(scope);
  if (!norm || !asset.hostname) return false;

  // Any reserved/metadata/private asset is un-matchable no matter what the
  // scope says. This is the last line of defence before a request goes out.
  if (asset.isPrivateOrReserved || asset.unsafeReason) return false;

  if (norm.isCidr) {
    if (!asset.isIpLiteral) return false;
    return cidrContains(scope.value.trim(), asset.hostname);
  }

  if (norm.isIpScope) {
    if (!asset.isIpLiteral) return false;
    return asset.hostname === norm.hostname;
  }

  // Control-proof records prove DNS control, not asset ownership.
  if (isControlProofHost(asset.hostname)) return false;

  if (scope.scopeType === 'wildcard_domain') {
    // `*.example.com` authorizes exactly one additional label, per the module
    // design rules. Deeper names need their own row or a `domain` scope.
    const suffix = `.${norm.hostname}`;
    if (!asset.hostname.endsWith(suffix)) return false;
    const label = asset.hostname.slice(0, asset.hostname.length - suffix.length);
    if (label.length === 0 || label.includes('.')) return false;
  } else if (scope.scopeType === 'domain') {
    if (!isHostWithin(asset.hostname, norm.hostname)) return false;
  } else {
    // Exact host match for everything else.
    if (asset.hostname !== norm.hostname) return false;
  }

  // Path-prefix containment for url/api scopes.
  if (scope.scopeType === 'url' || scope.scopeType === 'api') {
    const basePath = norm.path === '/' ? '/' : norm.path;
    if (basePath !== '/') {
      const assetPath = asset.path;
      if (assetPath !== basePath && !assetPath.startsWith(`${basePath}/`)) return false;
    }
  }

  return true;
}




// ---------------------------------------------------------------------------
// Rule evaluation (ports, paths, methods, schemes)
// ---------------------------------------------------------------------------

/** Methods that mutate state and always need per-action approval. */
export const STATE_CHANGING_METHODS: readonly string[] = [
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'CONNECT',
  'TRACE',
];

/** Methods a scanner may use without extra approval. */
export const SAFE_METHODS: readonly string[] = ['GET', 'HEAD', 'OPTIONS'];

function segmentMatches(ruleValue: string, actual: string): boolean {
  const rule = ruleValue.trim().toLowerCase();
  const target = actual.trim().toLowerCase();
  if (rule === target) return true;
  // Support a trailing `*` so `/api/v*` can cover `/api/v1`.
  if (rule.endsWith('*')) return target.startsWith(rule.slice(0, -1));
  return false;
}

/** Finds all rules of a kind that apply to the asset. */
function applicableRules(asset: ParsedAsset, rules: ScopeRule[], kind: ScopeRule['ruleKind']): ScopeRule[] {
  return rules.filter((rule) => {
    if (rule.ruleKind !== kind) return false;
    if (kind === 'port') {
      if (asset.port === null) return false;
      if (rule.valueEnd) {
        const lo = Number(rule.value.trim());
        const hi = Number(rule.valueEnd);
        if (!Number.isFinite(lo) || !Number.isFinite(hi)) return false;
        return asset.port >= lo && asset.port <= hi;
      }
      return Number(rule.value.trim()) === asset.port;
    }
    if (kind === 'path') {
      return segmentMatches(rule.value, asset.path);
    }
    return false;
  });
}

export interface RuleDecision {
  allowed: boolean;
  reason: string;
  /** True when a rule explicitly denies; callers must not override this. */
  denied: boolean;
}

/**
 * Applies scope rules to an asset. Deny always wins over allow, and when a
 * `port` allowlist exists any port absent from it is denied rather than
 * permitted by default.
 */
export function applyScopeRules(
  asset: ParsedAsset,
  rules: ScopeRule[],
  method?: string,
): RuleDecision {
  // 1. Port denylist.
  for (const rule of applicableRules(asset, rules.filter((r) => r.effect === 'deny'), 'port')) {
    return {
      allowed: false,
      reason: `port ${asset.port} is explicitly denied by scope rule`,
      denied: true,
    };
  }

  // 2. Path denylist.
  for (const rule of applicableRules(asset, rules.filter((r) => r.effect === 'deny'), 'path')) {
    return {
      allowed: false,
      reason: `path ${asset.path} is excluded by program rules`,
      denied: true,
    };
  }

  // 3. Scheme denylist.
  for (const rule of rules) {
    if (rule.ruleKind === 'scheme' && rule.effect === 'deny' && asset.scheme) {
      if (rule.value.trim().toLowerCase() === asset.scheme) {
        return { allowed: false, reason: `scheme ${asset.scheme} is denied by scope rule`, denied: true };
      }
    }
  }

  // 4. Method rules. State-changing methods require an explicit allow rule.
  if (method) {
    const upper = method.trim().toUpperCase();
    const methodDeny = rules.find(
      (rule) =>
        rule.ruleKind === 'method' && rule.effect === 'deny' && rule.value.trim().toUpperCase() === upper,
    );
    if (methodDeny) {
      return { allowed: false, reason: `HTTP method ${upper} is denied by scope rule`, denied: true };
    }
    if (STATE_CHANGING_METHODS.includes(upper)) {
      const methodAllow = rules.find(
        (rule) =>
          rule.ruleKind === 'method' && rule.effect === 'allow' && rule.value.trim().toUpperCase() === upper,
      );
      if (!methodAllow) {
        return {
          allowed: false,
          reason: `${upper} is state-changing and requires an explicit scope allow rule plus human approval`,
          denied: true,
        };
      }
    } else if (!SAFE_METHODS.includes(upper)) {
      return { allowed: false, reason: `HTTP method ${upper} is not on the allowlist`, denied: true };
    }
  }

  // 5. Port allowlist: when present, absence means deny.
  const portAllows = rules.filter((rule) => rule.ruleKind === 'port' && rule.effect === 'allow');
  if (portAllows.length > 0) {
    const permitted = portAllows.some((rule) => {
      if (rule.valueEnd) {
        const lo = Number(rule.value.trim());
        const hi = Number(rule.valueEnd);
        return (
          asset.port !== null && Number.isFinite(lo) && Number.isFinite(hi) && asset.port >= lo && asset.port <= hi
        );
      }
      return Number(rule.value.trim()) === asset.port;
    });
    if (!permitted) {
      return { allowed: false, reason: `port ${asset.port} is not on the scope port allowlist`, denied: true };
    }
  }

  return { allowed: true, reason: 'scope rules permit this asset', denied: false };
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

const denyDecision = (reason: string, validation: ScopeDecision['validation'] = 'out_of_scope'): ScopeDecision => ({
  allowed: false,
  reason,
  validation,
});

/**
 * The authoritative scope gate.
 *
 * Order of checks (each one short-circuits to a denial):
 *   1. Emergency stop.
 *   2. Asset parses and is not a blocked/private/metadata address.
 *   3. Target authorization, pause state and validity window.
 *   4. At least one scope row exists for the target.
 *   5. No active denylist row matches.
 *   6. At least one active allowlist row matches.
 *   7. Requested mode is permitted by the scope/target.
 *   8. Scope rules permit the port, path and method.
 *
 * Every failure mode returns `allowed: false`. There is no code path that
 * returns a permissive result on an error.
 */
export function evaluateScope(
  assetInput: string | ParsedAsset,
  scopes: ScopeRecord[],
  options: EvaluateScopeOptions = {},
): ScopeDecision {
  const now = options.now ?? new Date();

  if (options.emergencyStop) {
    return denyDecision('emergency stop is active: all scanning is halted', 'denied');
  }

  const asset = typeof assetInput === 'string' ? parseAsset(assetInput) : assetInput;
  if (!asset.hostname) {
    return denyDecision(`asset rejected: ${asset.unsafeReason ?? 'unparseable reference'}`);
  }
  if (asset.unsafeReason) {
    return denyDecision(`asset rejected: ${asset.unsafeReason}`, 'denied');
  }
  if (asset.isPrivateOrReserved) {
    return denyDecision('asset resolves to a private, reserved or metadata address', 'denied');
  }

  // 3. Target-level gates.
  const target = options.target;
  if (target) {
    if (target.authorizationStatus && target.authorizationStatus !== 'confirmed') {
      return denyDecision(`target authorization is "${target.authorizationStatus}", not confirmed`, 'denied');
    }
    if (target.status === 'paused') {
      return denyDecision('target is paused', 'denied');
    }
    if (target.status === 'archived' || target.status === 'expired') {
      return denyDecision(`target is ${target.status}`, 'expired');
    }
    if (target.validFrom && now.getTime() < Date.parse(target.validFrom)) {
      return denyDecision('target authorization window has not started yet', 'expired');
    }
    if (target.validUntil && now.getTime() >= Date.parse(target.validUntil)) {
      return denyDecision('target authorization has expired', 'expired');
    }
  }

  if (scopes.length === 0) {
    return denyDecision('no scope is configured for this target');
  }

  const targetScopes = scopes;

  // Expiry awareness: if every allowlist row exists but is expired, say so
  // explicitly rather than the vaguer "out of scope".
  const allowRows = targetScopes.filter((s) => s.isAllowlist);
  const activeAllow = allowRows.filter((s) => isScopeActive(s, now));
  if (allowRows.length > 0 && activeAllow.length === 0) {
    const paused = allowRows.some((s) => s.status === 'paused');
    return denyDecision(
      paused ? 'all scopes for this target are paused' : 'all scopes for this target have expired',
      'expired',
    );
  }

  // 5. Active denylist rows always win.
  for (const scope of targetScopes) {
    if (scope.isAllowlist) continue;
    if (!isScopeActive(scope, now)) continue;
    if (assetMatchesScope(asset, scope)) {
      return denyDecision(`asset is explicitly denied by scope "${scope.label}"`, 'denied');
    }
  }

  // 6. Find a matching active allowlist row.
  const matched = activeAllow.find((scope) => assetMatchesScope(asset, scope));
  if (!matched) {
    return denyDecision('asset is not covered by any active authorized scope');
  }

  // 7. Mode gating. Passive always allowed; active needs enablement.
  const mode = options.mode ?? 'passive';
  if (mode !== 'passive') {
    const scopeAllowsActive = matched.lowImpactActive || matched.intrusiveEnabled;
    const targetAllowsActive = target ? target.lowImpactActive || target.intrusiveEnabled : false;
    if (mode === 'low_impact_active' && !(scopeAllowsActive || targetAllowsActive)) {
      return denyDecision('low-impact active testing is not enabled for this scope', 'denied');
    }
    if (mode === 'intrusive') {
      if (!matched.intrusiveEnabled) {
        return denyDecision('intrusive testing is not enabled for this scope', 'denied');
      }
      if (target && !target.intrusiveEnabled) {
        return denyDecision('intrusive testing is not enabled for this target', 'denied');
      }
      if (matched.passiveOnly || (target && target.passiveOnly)) {
        return denyDecision('scope is passive-only, so intrusive testing is refused', 'denied');
      }
    }
    if (matched.passiveOnly) {
      return denyDecision('scope is marked passive-only', 'denied');
    }
  }

  // 8. Rules.
  const rules = matched.rules ?? [];
  const ruleDecision = applyScopeRules(asset, rules, options.method);
  if (!ruleDecision.allowed) {
    return denyDecision(ruleDecision.reason, 'denied');
  }

  const decision: ScopeDecision = {
    allowed: true,
    reason: ruleDecision.reason,
    scopeId: matched.id,
    validation: 'in_scope',
  };
  const allowedPorts = rules
    .filter((r) => r.ruleKind === 'port' && r.effect === 'allow')
    .map((r) => Number(r.value.trim()))
    .filter((n) => Number.isFinite(n));
  const deniedPorts = rules
    .filter((r) => r.ruleKind === 'port' && r.effect === 'deny')
    .map((r) => Number(r.value.trim()))
    .filter((n) => Number.isFinite(n));
  if (allowedPorts.length > 0) decision.allowedPorts = allowedPorts;
  if (deniedPorts.length > 0) decision.deniedPorts = deniedPorts;
  return decision;
}

