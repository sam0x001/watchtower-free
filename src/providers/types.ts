// src/providers/types.ts
// Provider adapter interface — every recon source must implement this.

export interface ProviderContext {
  /** Maximum response size the Worker is willing to accept. */
  maxResponseBytes: number;
  /** Per-provider request timeout. */
  timeoutMs: number;
  /** Optional KV cache binding. */
  cache?: KVNamespace;
  /** User agent string. */
  userAgent: string;
  /** A logger function for diagnostics. */
  log: (msg: string, fields?: Record<string, unknown>) => void;
}

export interface ProviderAsset {
  type: "domain" | "ip" | "certificate" | "url";
  value: string;
  normalized: string;
  source: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface ProviderResult {
  provider: string;
  assets: ProviderAsset[];
  fetchedAt: string;
  cacheHit: boolean;
  error?: string;
}

export interface ReconProvider {
  readonly name: string;
  readonly kind: "certificate_transparency" | "dns" | "subdomain" | "http" | "scanner" | "cve" | "cloud";
  discover(input: { host: string; }, ctx: ProviderContext): Promise<ProviderResult>;
}
