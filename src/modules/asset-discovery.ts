// src/modules/asset-discovery.ts
// Orchestrates Certificate Transparency + DNS discovery for a target.
//
// Returns a list of `Alert` objects — one per new subdomain, new IP, new
// certificate, or new DNS record. The scan consumer enqueues each as a
// notification message.

import type { Env } from "../env.js";
import type { CompiledScope } from "../security/scope.js";
import { checkHostInScope } from "../security/scope.js";
import { buildRegistry, runProviders, type ProviderRegistry } from "../providers/registry.js";
import {
  upsertAsset,
  upsertCertificate,
  upsertDnsRecord,
} from "../db/queries/assets.js";
import { normalizeDomain } from "../utils/domain.js";
import { LIMITS } from "../constants.js";
import type { ConsoleLogger } from "../audit/logger.js";
import { buildAlert, type Alert } from "./alerts.js";

export interface AssetDiscoveryResult {
  /** All new/changed assets detected during this scan — converted to alerts. */
  alerts: Alert[];
  outOfScope: number;
  errors: string[];
}

export async function discoverAssetsForTarget(
  env: Env,
  targetId: string,
  host: string,
  scope: CompiledScope,
  log: ConsoleLogger,
): Promise<AssetDiscoveryResult> {
  const registry: ProviderRegistry = buildRegistry();
  const ctx = {
    maxResponseBytes: LIMITS.MAX_CERT_PROVIDER_RESPONSE_BYTES,
    timeoutMs: 15_000,
    cache: env.CACHE,
    userAgent: env.USER_AGENT,
    log: (m: string, f?: Record<string, unknown>) => log.info(m, f),
  };

  const results = await runProviders([...registry.ct, ...registry.dns], { host }, ctx);

  const alerts: Alert[] = [];
  const errors: string[] = [];
  let outOfScope = 0;

  for (const r of results) {
    if (r.error) errors.push(`${r.provider}: ${r.error}`);

    for (const a of r.assets) {
      const scopeCheck = checkHostInScope(scope, a.normalized);
      if (!scopeCheck.allowed) {
        outOfScope++;
        // Out-of-scope assets are recorded but never alerted + never probed.
        await upsertAsset(env.DB, targetId, "subdomain", a.value, a.normalized, "out_of_scope", {
          source: a.source,
          reason: scopeCheck.reason,
        });
        continue;
      }

      // ---- CT provider assets: each name becomes a subdomain asset + (if serial present) a cert row.
      if (a.type === "certificate") {
        const subAsset = await upsertAsset(
          env.DB, targetId, "subdomain", a.value, a.normalized, "in_scope",
          { source: a.source },
        );

        if (subAsset.created) {
          alerts.push(buildAlert("new_subdomain", targetId, {
            asset_id: subAsset.id,
            asset_value: a.normalized,
            title: `New subdomain discovered: ${a.normalized}`,
            summary: `A new in-scope subdomain was discovered via ${a.source}.\n\nHostname: ${a.normalized}\nSource: ${a.source}\nConfidence: ${a.confidence}`,
            metadata: { source: a.source, confidence: a.confidence },
          }));
        }

        // If the CT provider included certificate metadata, persist + alert on new serials.
        if (a.metadata?.serial) {
          const issuer = String(a.metadata?.issuer ?? "unknown");
          const serial = String(a.metadata?.serial);
          const notBefore = (a.metadata?.not_before as string | null) ?? null;
          const notAfter = (a.metadata?.not_after as string | null) ?? null;

          const cert = await upsertCertificate(
            env.DB, subAsset.id, issuer, serial, notBefore, notAfter, [a.value],
          );
          if (cert.created) {
            alerts.push(buildAlert("new_certificate", targetId, {
              asset_id: subAsset.id,
              asset_value: `${a.normalized} (serial ${serial})`,
              title: `New TLS certificate issued for ${a.normalized}`,
              summary:
                `A new TLS certificate was issued for ${a.normalized}.\n\n` +
                `Issuer: ${issuer}\nSerial: ${serial}\nValid from: ${notBefore ?? "unknown"}\nValid until: ${notAfter ?? "unknown"}\nSource: ${a.source}`,
              metadata: { issuer, serial, not_before: notBefore, not_after: notAfter },
            }, "high"));
          }
        }
      }

      // ---- DNS provider assets: each resolved IP becomes an IP asset.
      if (a.type === "ip") {
        const ipAsset = await upsertAsset(
          env.DB, targetId, "ip", a.value, a.value, "in_scope",
          { source: a.source, hostname: a.metadata?.hostname ?? null },
        );
        if (ipAsset.created) {
          alerts.push(buildAlert("new_ip", targetId, {
            asset_id: ipAsset.id,
            asset_value: a.value,
            title: `New IP address resolved: ${a.value}`,
            summary: `A new in-scope IP was discovered during DNS resolution.\n\nIP: ${a.value}\nHostname: ${a.metadata?.hostname ?? host}\nSource: ${a.source}`,
            metadata: { ip: a.value, hostname: a.metadata?.hostname ?? null },
          }));
        }
      }
    }

    // ---- DNS provider returns records too (A/AAAA/CNAME/MX/etc.) — store + alert on new ones.
    // The DoH provider exposes them via the result's `metadata.records` field.
    const records = (r as { metadata?: { records?: { type: string; name: string; value: string; ttl: number | null }[] } }).metadata?.records;
    if (records && records.length > 0) {
      // Find or create the host asset to attach DNS records to.
      const hostAsset = await upsertAsset(
        env.DB, targetId, "subdomain", host, host, "in_scope",
        { source: r.provider },
      );
      for (const rec of records) {
        const dnsRes = await upsertDnsRecord(
          env.DB, hostAsset.id, rec.type, rec.name, rec.value, rec.ttl,
        );
        if (dnsRes.created) {
          alerts.push(buildAlert("new_dns_record", targetId, {
            asset_id: hostAsset.id,
            asset_value: `${rec.type} ${rec.name} → ${rec.value}`,
            title: `New DNS record: ${rec.type} for ${rec.name}`,
            summary:
              `A new DNS record was observed.\n\n` +
              `Type: ${rec.type}\nName: ${rec.name}\nValue: ${rec.value}\nTTL: ${rec.ttl ?? "n/a"}\nSource: ${r.provider}`,
            metadata: { record_type: rec.type, name: rec.name, value: rec.value, ttl: rec.ttl },
          }, "low"));
        }
      }
    }
  }

  return { alerts, outOfScope, errors };
}

/**
 * Returns the parent domain of `host` if it's already normalized, otherwise
 * the normalized form.
 */
export function getEffectiveHost(host: string): string | null {
  return normalizeDomain(host);
}
