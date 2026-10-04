// src/queues/scan-runner.ts
// Core scan pipeline. One bounded pass over a target per invocation:
//
//   passive (CT logs + DoH DNS)  →  subdomain bruteforce chunk  →  HTTP probe
//   rotation (services, technologies, CVE matching, JS analysis, fuzzing)
//
// Everything is chunked so it fits the Cloudflare Workers free tier:
//   * a wall-clock deadline (FREE_TIER_SCAN_TIMEOUT_MS) is checked between
//     hosts, so a pass always finishes inside the invocation window;
//   * the bruteforce wordlist and the fuzz wordlists keep their cursor in KV and
//     advance a bounded slice per tick;
//   * HTTP probes are rotated with `assets.last_probed`, so every subdomain is
//     eventually probed without probing all of them at once;
//   * a per-target D1 lock (table `locks`) keeps two ticks from scanning the
//     same target concurrently.
//
// No alert is ever sent from here directly: alerts are returned to the caller,
// which either enqueues `notification` jobs (cron path) or writes them straight
// into the chat (the /scan path, so the operator sees first results immediately).

import type { Env } from "../env.js";
import { num } from "../env.js";
import { LIMITS } from "../constants.js";
import { getTargetById, listScopeEntries } from "../db/queries/targets.js";
import { getFeatureMap, type FeatureMap } from "../db/queries/features.js";
import { compileScope, checkHostInScope, checkUrlInScope, type CompiledScope } from "../scope/index.js";
import { LockClient } from "../db/distributed-lock.js";
import { upsertAsset, upsertService, upsertTechnology } from "../db/queries/assets.js";
import { discoverAssetsForTarget } from "../modules/asset-discovery.js";
import { analyzeJsForAsset } from "../modules/js-analyzer.js";
import { matchCvesForTech } from "../modules/cve-matcher.js";
import { getWildcardIps, runBruteforceChunk } from "../modules/dns-bruteforce.js";
import { runFuzzChunk, FUZZ_PROFILE } from "../modules/wordlist.js";
import { HttpxProvider } from "../providers/http/httpx-adapter.js";
import type { ProviderContext } from "../providers/types.js";
import { buildAlert, type Alert } from "../modules/alerts.js";
import { claimPendingJobs, completeJob, failJob, enqueueJob } from "../db/job-queue.js";
import { log, newRequestId, type ConsoleLogger } from "../lib/console-logger.js";
import { sendMessage } from "../telegram/webhook.js";

export type ScanTrigger = "manual" | "cron" | "continuation";

// ---------------------------------------------------------------------------
// Port rotation (port_watch)
//
// Fourteen common HTTP(S) ports, rotated one port per probed host per tick so
// the extra probes stay inside the free-tier budget:
//   80 443 8080 8443 8000 8888 3000 5000 8001 8081 8444 9443 9000 7001
// 80/443 are always covered by the main probes; the rotation covers the rest
// plus a periodic re-check of 80/443 themselves.
// ---------------------------------------------------------------------------

/** Non-standard ports rotated one-per-host through the probe queue. */
export const PORT_WATCH_ROTATION = [8080, 8443, 8000, 8888, 3000, 5000, 8001, 8081, 8444, 9443, 9000, 7001] as const;

function isHttpsPort(port: number): boolean {
  return port === 443 || port === 8443 || port === 8444 || port === 9443;
}

/** KV cursor for the port rotation: `pw:<targetId>` (index into the array). */
async function portCursor(env: Env, targetId: string): Promise<number> {
  try {
    const raw = await env.CACHE.get(`pw:${targetId}`);
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) && n >= 0 ? n % PORT_WATCH_ROTATION.length : 0;
  } catch {
    return 0;
  }
}

async function savePortCursor(env: Env, targetId: string, index: number): Promise<void> {
  try {
    await env.CACHE.put(`pw:${targetId}`, String(index));
  } catch {
    // A lost cursor only means the rotation restarts — never fatal.
  }
}

// ---------------------------------------------------------------------------
// Result shapes
// ---------------------------------------------------------------------------

export interface ScanStats {
  /** Subdomains recorded for the first time during this pass. */
  subdomainsFound: number;
  /** TLS certificates recorded for the first time during this pass. */
  certsFound: number;
  /** DNS records recorded for the first time during this pass. */
  dnsRecordsFound: number;
  /** Hosts that answered an HTTP probe during this pass. */
  liveHosts: number;
  /** Technologies fingerprinted for the first time. */
  newTechs: number;
  /** Secret candidates recorded for the first time (values are never stored). */
  secretsFound: number;
  /** CVE matches recorded for the first time. */
  cvesFound: number;
  /** Sensitive paths recorded for the first time by the wordlist fuzzer. */
  fuzzFindings: number;
  /** Fuzz requests attempted during this pass. */
  fuzzRequests: number;
  /** Bruteforce hits discarded because they only resolved to wildcard IPs. */
  wildcardSkipped: number;
  /** Passive-phase assets the scope refused (exclusions / out of scope). */
  outOfScope: number;
  /** Exactly how many hosts were probed this pass. */
  hostsProbed: number;
  /** Ports probed this pass (port_watch shares the same rotation slot). */
  portsProbed: number;
  /** Ports that answered on a non-standard port (alerts ride the same list). */
  portsOpen: number;
  /** Bruteforce cursor bookkeeping for the /scan summary. */
  bruteforce: { resolved: number; skippedWildcard: number; cursor: number; total: number; done: boolean } | null;
  /** First few new subdomains — used by the /scan summary message. */
  topSubdomains: string[];
  /** True when the pass stopped early because the wall-clock budget ran out. */
  deadlineReached: boolean;
  errors: string[];
}

export interface ScanRunResult {
  ok: boolean;
  /** Present when ok === false. */
  error?: string;
  /** False when retrying the same scan can never succeed (paused/missing target). */
  retryable: boolean;
  targetId: string;
  targetName: string;
  organizationId: string;
  alerts: Alert[];
  stats: ScanStats;
}

export interface ScanRunOptions {
  trigger?: ScanTrigger;
  /**
   * How much of the pipeline to run.
   *   "passive" — certificate transparency + DNS records only. Third-party
   *               API calls that answer in seconds, so this is what the inline
   *               /scan path runs; everything else is left to the cron.
   *   "full"    — the whole chunked pass (the default, used by the cron).
   */
  phases?: "passive" | "full";
  /** `scans.id` row to mirror the lifecycle onto. */
  scanId?: string | null;
  /** `job_queue.id` that caused this run (lock holder id + log correlation). */
  jobId?: string | null;
  /** Wall-clock budget override (the /scan path uses a tighter budget). */
  deadlineMs?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Budget used by the inline /scan pass (the webhook must answer quickly). */
export const INLINE_SCAN_BUDGET_MS = 40_000;

/**
 * How many individual asset alerts /scan prints straight into the chat.
 * Anything past this rides the notification queue instead, so nothing is
 * silently dropped — see deliverInlineAlerts.
 */
const INLINE_ALERT_LIMIT = 12;

function emptyStats(): ScanStats {
  return {
    subdomainsFound: 0, certsFound: 0, dnsRecordsFound: 0, liveHosts: 0,
    newTechs: 0, secretsFound: 0,
    cvesFound: 0, fuzzFindings: 0, fuzzRequests: 0, wildcardSkipped: 0,
    outOfScope: 0, hostsProbed: 0, portsProbed: 0, portsOpen: 0, bruteforce: null,
    topSubdomains: [], deadlineReached: false, errors: [],
  };
}

function providerCtx(env: Env, logger: ConsoleLogger): ProviderContext {
  return {
    maxResponseBytes: LIMITS.MAX_CERT_PROVIDER_RESPONSE_BYTES,
    timeoutMs: 15_000,
    cache: env.CACHE,
    userAgent: env.USER_AGENT,
    log: (m: string, f?: Record<string, unknown>) => logger.info(m, f),
  };
}

/** Findings-style counters packaged for the `scans` row. */
function changesDetected(stats: ScanStats): number {
  return stats.subdomainsFound + stats.liveHosts + stats.newTechs + stats.cvesFound + stats.fuzzFindings;
}

/** Mirror the job_queue lifecycle onto the canonical `scans` row. */
async function updateScanRow(
  db: D1Database,
  scanId: string | null | undefined,
  status: "queued" | "running" | "completed" | "failed",
  opts: {
    stop_reason?: string | null;
    errors?: string[];
    stats?: ScanStats;
    reset_started?: boolean;
  } = {},
): Promise<void> {
  if (!scanId) return;
  const now = new Date().toISOString();
  const sets = ["status = ?", "updated_at = ?"];
  const binds: (string | number | null)[] = [status, now];

  if (status === "running") {
    sets.push("started_at = ?");
    binds.push(now);
  }
  if (opts.reset_started) {
    sets.push("started_at = NULL");
  }
  if (status === "completed" || status === "failed") {
    sets.push("finished_at = ?");
    binds.push(now);
  }
  if (opts.stop_reason !== undefined) {
    sets.push("stop_reason = ?");
    binds.push(opts.stop_reason ?? null);
  }
  if (opts.errors && opts.errors.length > 0) {
    sets.push("errors_json = ?");
    binds.push(JSON.stringify(opts.errors.slice(0, 20)));
  }
  if (opts.stats) {
    sets.push("assets_seen = ?", "changes_detected = ?", "findings_created = ?");
    binds.push(
      opts.stats.subdomainsFound + opts.stats.hostsProbed,
      changesDetected(opts.stats),
      opts.stats.secretsFound + opts.stats.cvesFound + opts.stats.fuzzFindings,
    );
  }
  binds.push(scanId);

  // Never resurrect a scan the operator already cancelled.
  await db
    .prepare(`UPDATE scans SET ${sets.join(", ")} WHERE id = ? AND status NOT IN ('cancelled')`)
    .bind(...binds)
    .run();
}

/** True when an identical alert was already delivered inside the dedupe window. */
async function notificationAlreadySent(db: D1Database, dedupeKey: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - LIMITS.NOTIFICATION_DEDUPE_WINDOW_HOURS * 3_600_000).toISOString();
  const row = await db
    .prepare(`SELECT id FROM notifications WHERE dedupe_key = ? AND status = 'sent' AND created_at > ? LIMIT 1`)
    .bind(dedupeKey, cutoff)
    .first<{ id: string }>();
  return !!row;
}

/** Record an alert as already delivered (baseline) so the cron never re-sends it. */
async function recordNotificationSent(
  db: D1Database,
  alert: Alert,
  targetId: string,
  organizationId: string,
  destination: string,
): Promise<void> {
  const now = new Date().toISOString();
  const id = `notif_${crypto.randomUUID()}`;
  await db
    .prepare(
      `INSERT INTO notifications (
         id, organization_id, target_id, finding_id, channel, destination,
         alert_type, severity, title, body_redacted, dedupe_key, status,
         attempts, sent_at, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'telegram', ?, ?, ?, ?, ?, ?, 'sent', 1, ?, ?, ?)`,
    )
    .bind(
      id, organizationId, targetId,
      (alert.metadata["finding_id"] as string | undefined) ?? null,
      destination, alert.type, alert.severity, alert.title,
      alert.summary.slice(0, 4000), alert.dedup_key, now, now, now,
    )
    .run();
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function collectSubdomainStats(batch: Alert[], stats: ScanStats): void {
  for (const a of batch) {
    if (a.type === "new_certificate") {
      stats.certsFound++;
      continue;
    }
    if (a.type === "new_dns_record") {
      stats.dnsRecordsFound++;
      continue;
    }
    if (a.type !== "new_subdomain") continue;
    stats.subdomainsFound++;
    const value = String(a.metadata["asset_value"] ?? "");
    if (value && stats.topSubdomains.length < 10) stats.topSubdomains.push(value);
  }
}

// ---------------------------------------------------------------------------
// The scan pass
// ---------------------------------------------------------------------------

/**
 * Run ONE bounded scan pass for `targetId`.
 *
 * The caller owns the job/scan lifecycle — this function only takes the
 * per-target lock, does the work, and reports what it found.
 */
export async function runScanForTarget(
  env: Env,
  targetId: string,
  opts: ScanRunOptions = {},
): Promise<ScanRunResult> {
  const logger = log;
  const stats = emptyStats();
  const alerts: Alert[] = [];
  const trigger: ScanTrigger = opts.trigger ?? "cron";
  // "passive" stops after the CT/DNS phase: those are third-party API calls
  // that answer in seconds, which is exactly what an interactive /scan wants.
  // The heavy phases stay on the cron so the webhook invocation stays inside
  // the Workers free-tier wall-clock + CPU budget.
  const passiveOnly = (opts.phases ?? "full") === "passive";

  // ---- 1. Target + scope -------------------------------------------------
  const target = await getTargetById(env.DB, targetId);
  if (!target) {
    return { ok: false, error: "target not found", retryable: false, targetId, targetName: "", organizationId: "", alerts, stats };
  }
  if (target.paused) {
    return { ok: false, error: "target is paused", retryable: false, targetId, targetName: target.name, organizationId: target.organization_id, alerts, stats };
  }

  const scopeEntries = await listScopeEntries(env.DB, targetId);
  const scope: CompiledScope = compileScope(target, scopeEntries);
  const host = target.name;

  // Per-target feature toggles (defaults keep every existing target fully on,
  // except nuclei which needs a runner the bot doesn't have).
  const features: FeatureMap = await getFeatureMap(env.DB, targetId);

  // ---- 2. Per-target lock ------------------------------------------------
  const holderId = opts.jobId ? `scan:${opts.jobId}` : `scan:${newRequestId()}`;
  const budgetMs = opts.deadlineMs ?? num(env.FREE_TIER_SCAN_TIMEOUT_MS, 60_000);
  const lock = new LockClient(env.DB, `target:${targetId}`);
  const locked = await lock.acquire(holderId, budgetMs + 60_000);
  if (!locked) {
    return {
      ok: false, error: "target busy (another scan is running)", retryable: true,
      targetId, targetName: target.name, organizationId: target.organization_id, alerts, stats,
    };
  }

  const deadline = Date.now() + budgetMs;
  const pctx = providerCtx(env, logger);

  try {
    logger.info("scan.start", { targetId, host, trigger, budgetMs, phases: opts.phases ?? "full", scopeEntries: scopeEntries.length });

    // ---- 3. Passive phase: certificate transparency + DNS records --------
    // A disabled subdomain_enum skips the CT/DoH providers entirely.
    if (features.subdomain_enum) {
      const discovery = await discoverAssetsForTarget(env, targetId, host, scope, logger);
      alerts.push(...discovery.alerts);
      stats.outOfScope += discovery.outOfScope;
      stats.errors.push(...discovery.errors);
      collectSubdomainStats(discovery.alerts, stats);
    }

    if (passiveOnly) {
      logger.info("scan.passive_complete", {
        targetId, host, trigger, alerts: alerts.length,
        subdomains: stats.subdomainsFound,
      });
      return {
        ok: true, retryable: true, targetId, targetName: target.name,
        organizationId: target.organization_id, alerts, stats,
      };
    }

    // ---- 4. Bruteforce phase: one bounded chunk of the wordlist ----------
    if (features.dns_brute && Date.now() < deadline) {
      const wildcardIps = await getWildcardIps(env, targetId, host, pctx);
      const bf = await runBruteforceChunk(
        env, targetId, host, scope, wildcardIps, pctx,
        num(env.BRUTEFORCE_CHUNK, 300),
        num(env.BRUTEFORCE_CONCURRENCY, 16),
      );
      alerts.push(...bf.alerts);
      stats.wildcardSkipped += bf.skippedWildcard;
      stats.bruteforce = {
        resolved: bf.resolved, skippedWildcard: bf.skippedWildcard,
        cursor: bf.cursor, total: bf.total, done: bf.done,
      };
      collectSubdomainStats(bf.alerts, stats);
    } else {
      stats.deadlineReached = true;
    }

    // ---- 5. Probe rotation (never-probed / least-recently-probed first) --
    const due = await env.DB
      .prepare(
        `SELECT id, identifier FROM assets
          WHERE target_id = ? AND asset_type = 'subdomain' AND status = 'active'
            AND scope_state = 'allowed'
          ORDER BY (last_probed IS NULL) DESC, last_probed ASC, first_seen ASC
          LIMIT ?`,
      )
      .bind(targetId, num(env.PROBE_LIMIT_PER_SCAN, 5))
      .all<{ id: string; identifier: string }>();

    for (const asset of due.results ?? []) {
      if (Date.now() >= deadline) {
        stats.deadlineReached = true;
        break;
      }
      const outcome = await probeHost(
        env, targetId, asset.identifier, scope, pctx, features, deadline,
      );
      alerts.push(...outcome.alerts);
      stats.hostsProbed++;
      if (outcome.live) stats.liveHosts++;
      stats.portsProbed += outcome.portsProbed;
      stats.portsOpen += outcome.portsOpen;
      stats.newTechs += outcome.newTechs;
      stats.secretsFound += outcome.secretsFound;
      stats.cvesFound += outcome.cvesFound;
      stats.fuzzFindings += outcome.fuzzFindings;
      stats.fuzzRequests += outcome.fuzzRequests;
      stats.errors.push(...outcome.errors);

      const now = new Date().toISOString();
      await env.DB
        .prepare(`UPDATE assets SET last_probed = ?, last_seen = ? WHERE id = ?`)
        .bind(now, now, asset.id)
        .run();
    }

    logger.info("scan.complete", {
      targetId, host, trigger, alerts: alerts.length,
      subdomains: stats.subdomainsFound, live: stats.liveHosts, techs: stats.newTechs,
      secrets: stats.secretsFound, cves: stats.cvesFound, fuzz: stats.fuzzFindings,
      hostsProbed: stats.hostsProbed, deadlineReached: stats.deadlineReached,
    });

    return {
      ok: true, retryable: true, targetId, targetName: target.name,
      organizationId: target.organization_id, alerts, stats,
    };
  } catch (err) {
    logger.error("scan.failed", { targetId, err: String(err) });
    stats.errors.push(String(err));
    return {
      ok: false, error: String(err), retryable: true, targetId,
      targetName: target.name, organizationId: target.organization_id, alerts, stats,
    };
  } finally {
    await lock.release(holderId).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Single-host probing
// ---------------------------------------------------------------------------

interface HostProbeOutcome {
  alerts: Alert[];
  live: boolean;
  portsProbed: number;
  portsOpen: number;
  newTechs: number;
  secretsFound: number;
  cvesFound: number;
  fuzzFindings: number;
  fuzzRequests: number;
  errors: string[];
}

/** KV cursor for the fuzz wordlists: `fuzz:<targetId>:<host>`. */
async function fuzzCursor(env: Env, targetId: string, host: string): Promise<number> {
  try {
    const raw = await env.CACHE.get(`fuzz:${targetId}:${host}`);
    if (!raw) return 0;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : 0;
  } catch {
    return 0;
  }
}

async function saveFuzzCursor(env: Env, targetId: string, host: string, offset: number): Promise<void> {
  try {
    await env.CACHE.put(`fuzz:${targetId}:${host}`, String(offset));
  } catch {
    // A lost cursor only means the wordlist restarts — never fatal.
  }
}

/**
 * Probe one host: HTTP service + technologies + CVE matches, then (only for a
 * real page) JavaScript analysis, one chunk of wordlist fuzzing, and the one
 * rotated extra port for the tick.
 *
 * The target's feature map gates every phase: disabled work costs zero
 * requests. `status_watch` gates service/tech storage + change alerts (status
 * and redirect changes included); `fuzz_files` gates the common-file fuzz
 * chunk; `deep_fuzz` doubles it on freshly created URL assets; `js_changes`
 * gates JS discovery; `port_watch` gates the extra-port rotation.
 */
async function probeHost(
  env: Env,
  targetId: string,
  host: string,
  scope: CompiledScope,
  pctx: ProviderContext,
  features: FeatureMap,
  deadline: number,
): Promise<HostProbeOutcome> {
  const out: HostProbeOutcome = {
    alerts: [], live: false, portsProbed: 0, portsOpen: 0,
    newTechs: 0, secretsFound: 0,
    cvesFound: 0, fuzzFindings: 0, fuzzRequests: 0, errors: [],
  };

  // Freshness: the URL asset didn't exist before this probe. Passing it to
  // the fuzz stage makes `deep_fuzz` a deeper pass on NEW hosts only.
  let freshHost = false;

  // Exclusions are honoured BEFORE a single packet is sent.
  const scopeCheck = checkHostInScope(scope, host);
  if (!scopeCheck.allowed) {
    out.errors.push(`skipped ${host}: ${scopeCheck.reason}`);
    return out;
  }

  const httpx = new HttpxProvider();
  let probe = await httpx.probeUrl(`https://${host}/`, host, pctx, scope);
  if (!probe) probe = await httpx.probeUrl(`http://${host}/`, host, pctx, scope);
  if (!probe) return out; // nothing answered on 443 or 80
  out.live = true;

  // A redirect (3xx final URL on another host) carries no fingerprintable body.
  // It is still a change worth reporting, then probing stops here.
  if (probe.status >= 300 && probe.status < 400) {
    return out;
  }

  // ---- URL asset + HTTP service -----------------------------------------
  const urlAsset = await upsertAsset(env.DB, targetId, "url", probe.finalUrl, probe.finalUrl, "in_scope", {
    title: probe.title, server: probe.server, status: probe.status,
  });
  freshHost = urlAsset.created;

  // With status_watch OFF the service row is neither stored nor alerted on —
  // the probe result then feeds only tech/CVE/JS/fuzz stages below.
  if (features.status_watch) {
    const port = probe.url.startsWith("https://") ? 443 : 80;
    const svc = await upsertService(
      env.DB, urlAsset.id, port, "tcp", null, null, probe.status, probe.title, probe.server,
    );

    if (svc.created) {
      out.alerts.push(buildAlert("new_service", targetId, {
        asset_id: urlAsset.id,
        asset_value: probe.finalUrl,
        title: `Live host: ${host}`,
        summary:
          `A new in-scope HTTP service answered.\n\n` +
          `URL: ${probe.finalUrl}\nStatus: ${probe.status}\n` +
          `Title: ${probe.title ?? "—"}\nServer: ${probe.server ?? "—"}`,
        metadata: {
          url: probe.finalUrl, status: probe.status,
          title: probe.title, server: probe.server, port,
        },
      }));
    }

    for (const change of svc.changes) {
      const alertType = change.field === "title"
        ? "service_title_changed"
        : change.field === "status"
          ? "service_status_changed"
          : "service_header_changed";
      const label = change.field === "title"
        ? "Page title"
        : change.field === "status"
          ? "HTTP status"
          : "Server header";
      out.alerts.push(buildAlert(alertType, targetId, {
        asset_id: urlAsset.id,
        asset_value: probe.finalUrl,
        title: `${label} changed on ${host}`,
        summary:
          `An in-scope HTTP service changed.\n\n` +
          `URL: ${probe.finalUrl}\nField: ${label}\nBefore: ${change.before}\nAfter: ${change.after}\n\n` +
          `Usually a deployment — worth a look if you did not ship it.`,
        metadata: { url: probe.finalUrl, field: change.field, before: change.before, after: change.after },
      }, change.field === "status" ? "medium" : "low"));
    }
  }

  // ---- Technologies + CVE matching (gated by status_watch) ---------------
  if (features.status_watch) {
    for (const tech of probe.technologies) {
      const techRes = await upsertTechnology(env.DB, urlAsset.id, tech.name, tech.version, 0.7, "httpx-worker");

      if (techRes.created) {
        out.newTechs++;
        out.alerts.push(buildAlert("new_technology", targetId, {
          asset_id: urlAsset.id,
          asset_value: `${host}:${tech.name}`,
          title: `New technology on ${host}: ${tech.name}${tech.version ? ` ${tech.version}` : ""}`,
          summary:
            `A technology was fingerprinted on an in-scope host.\n\n` +
            `Host: ${host}\nURL: ${probe.finalUrl}\n` +
            `Technology: ${tech.name}${tech.version ? ` ${tech.version}` : " (version unknown)"}\nConfidence: 70%`,
          metadata: { url: probe.finalUrl, technology: tech.name, version: tech.version },
        }));
      } else if (techRes.versionChanged) {
        out.alerts.push(buildAlert("technology_version_changed", targetId, {
          asset_id: urlAsset.id,
          asset_value: `${host}:${tech.name}`,
          title: `${tech.name} version changed on ${host}`,
          summary:
            `A fingerprinted technology changed version.\n\n` +
            `Host: ${host}\nTechnology: ${tech.name}\n` +
            `Before: ${techRes.previousVersion ?? "unknown"}\nAfter: ${tech.version ?? "unknown"}`,
          metadata: {
            url: probe.finalUrl, technology: tech.name,
            before: techRes.previousVersion, after: tech.version,
          },
        }, "medium"));
      }

      // CVE correlation only makes sense for versioned, mapped technologies.
      if (Date.now() < deadline) {
        const cve = await matchCvesForTech(env, targetId, urlAsset.id, host, probe.finalUrl, tech, pctx);
        out.cvesFound += cve.newCves;
        out.alerts.push(...cve.alerts);
      }
    }
  }

  // Deeper passive work needs a real page, not an error response.
  if (probe.status >= 400) return out;

  // ---- JavaScript discovery + secret scan (gated by js_changes) ----------
  if (features.js_changes) {
    const js = await analyzeJsForAsset(
      env, targetId, urlAsset.id, probe.finalUrl, scope,
      env.REDACTION_SALT ?? "fallback-redaction-salt",
    );
    out.alerts.push(...js.alerts);
    out.secretsFound += js.redactedSecretsStored;
    out.errors.push(...js.errors);
  }

  // ---- Common-file fuzz chunk (gated by fuzz_files) ----------------------
  // Freshly discovered hosts get a doubled slice when deep_fuzz is on.
  if (features.fuzz_files && Date.now() < deadline) {
    const budget = freshHost && features.deep_fuzz
      ? num(env.FUZZ_REQUESTS_PER_TICK, 40) * 2
      : num(env.FUZZ_REQUESTS_PER_TICK, 40);
    const offset = await fuzzCursor(env, targetId, host);
    const fuzz = await runFuzzChunk(env, probe.finalUrl, targetId, scope, offset, {
      ...FUZZ_PROFILE,
      maxRequests: budget,
    });
    out.fuzzRequests += fuzz.results.length;
    out.fuzzFindings += fuzz.alerts.length;
    out.alerts.push(...fuzz.alerts);
    if (fuzz.newOffset !== offset || fuzz.done) {
      await saveFuzzCursor(env, targetId, host, fuzz.done ? 0 : fuzz.newOffset);
    }
  }

  // ---- Extra port for the tick (gated by port_watch) ---------------------
  if (features.port_watch && Date.now() < deadline) {
    const index = await portCursor(env, targetId);
    const port = PORT_WATCH_ROTATION[index]!;
    await savePortCursor(env, targetId, (index + 1) % PORT_WATCH_ROTATION.length);
    const portOutcome = await probePort(env, targetId, urlAsset.id, host, port, scope, pctx);
    out.portsProbed += portOutcome.probed ? 1 : 0;
    out.portsOpen += portOutcome.open ? 1 : 0;
    out.alerts.push(...portOutcome.alerts);
  }

  return out;
}

// ---------------------------------------------------------------------------
// Extra-port probing (port_watch)
//
// One non-standard port per probed host per tick: the URL is scope-checked
// like everything else, and an answering service is stored/compared with the
// same service machinery — so re-runs only alert on real changes.
// ---------------------------------------------------------------------------

interface PortProbeOutcome {
  probed: boolean;
  open: boolean;
  alerts: Alert[];
}

async function probePort(
  env: Env,
  targetId: string,
  urlAssetId: string,
  host: string,
  port: number,
  scope: CompiledScope,
  pctx: ProviderContext,
): Promise<PortProbeOutcome> {
  const scheme = isHttpsPort(port) ? "https" : "http";
  const url = `${scheme}://${host}:${port}/`;
  const checked = checkUrlInScope(scope, url);
  if (!checked.allowed) return { probed: false, open: false, alerts: [] };

  const httpx = new HttpxProvider();
  let probe = null;
  try {
    probe = await httpx.probeUrl(url, host, pctx, scope);
  } catch {
    return { probed: true, open: false, alerts: [] };
  }
  if (!probe || probe.status >= 500) return { probed: true, open: false, alerts: [] };

  const svc = await upsertService(
    env.DB, urlAssetId, port, "tcp", null, null, probe.status, probe.title, probe.server,
  );
  const alerts: Alert[] = [];

  if (svc.created) {
    alerts.push(buildAlert("new_service", targetId, {
      asset_id: urlAssetId,
      asset_value: probe.finalUrl,
      title: `Open port on ${host}: ${port}`,
      summary:
        `A service answered on a watched non-standard port.\n\n` +
        `URL: ${probe.finalUrl}\nStatus: ${probe.status}\n` +
        `Title: ${probe.title ?? "—"}\nServer: ${probe.server ?? "—"}`,
      metadata: {
        url: probe.finalUrl, status: probe.status,
        title: probe.title, server: probe.server, port,
      },
    }));
  }

  for (const change of svc.changes) {
    alerts.push(buildAlert("service_status_changed", targetId, {
      asset_id: urlAssetId,
      asset_value: probe.finalUrl,
      title: `Service changed on ${host}:${port}`,
      summary:
        `A watched port's service changed.\n\n` +
        `URL: ${probe.finalUrl}\nField: ${change.field}\nBefore: ${change.before}\nAfter: ${change.after}`,
      metadata: { url: probe.finalUrl, field: change.field, before: change.before, after: change.after, port },
    }, "medium"));
  }

  return { probed: true, open: true, alerts };
}

// ---------------------------------------------------------------------------
// Cron path: pending scan jobs
// ---------------------------------------------------------------------------

/**
 * Claim and run up to FREE_TIER_MAX_JOBS_PER_CRON scan jobs, then turn every
 * alert they produced into a `notification` job for the dispatcher.
 */
export async function runPendingScans(
  env: Env,
  _ctx: ExecutionContext,
): Promise<{ claimed: number; completed: number; failed: number; alertsEnqueued: number }> {
  const maxJobs = num(env.FREE_TIER_MAX_JOBS_PER_CRON, 2);
  const timeoutMs = num(env.FREE_TIER_SCAN_TIMEOUT_MS, 60_000);
  const jobs = await claimPendingJobs(env.DB, "scan", maxJobs, timeoutMs + 30_000);

  let completed = 0;
  let failed = 0;
  let alertsEnqueued = 0;

  for (const job of jobs) {
    const targetId = String(job.payload["target_id"] ?? "");
    const scanId = (job.payload["job_id"] as string | undefined) ?? null;
    const trigger = (job.payload["triggered_by"] as ScanTrigger | undefined) ?? "cron";

    if (!targetId) {
      await failJob(env.DB, job.id, "scan job without a target_id");
      failed++;
      continue;
    }

    const result = await runScanForTarget(env, targetId, {
      trigger, scanId, jobId: job.id, deadlineMs: timeoutMs,
    });

    if (result.ok) {
      await updateScanRow(env.DB, scanId, "completed", { stats: result.stats });
      await completeJob(env.DB, job.id, { summary: `${result.alerts.length} alerts` });
      alertsEnqueued += await enqueueAlertNotifications(env, result);
      completed++;
      continue;
    }

    // A paused or deleted target can never succeed — drop it, don't retry.
    if (!result.retryable) {
      await updateScanRow(env.DB, scanId, "failed", { stop_reason: result.error ?? "unknown error" });
      await completeJob(env.DB, job.id);
      log.info("scan.skipped", { targetId, reason: result.error ?? "unknown" });
      continue;
    }

    const error = result.error ?? "unknown error";
    await failJob(env.DB, job.id, error, { retry_after_seconds: 60 * Math.max(1, job.attempts) });
    const terminal = job.attempts >= job.max_attempts;
    await updateScanRow(env.DB, scanId, terminal ? "failed" : "queued", {
      stop_reason: terminal ? error : null,
      errors: [error],
      reset_started: !terminal,
    });
    failed++;

    await enqueueJob(env.DB, "notification", {
      organization_id: result.organizationId,
      target_id: targetId,
      channel: "telegram",
      severity: "high",
      payload: {
        title: `Scan failed for ${result.targetName || targetId}`,
        summary: `Scan job ${job.id} failed: ${error.slice(0, 500)}`,
        change_type: "scan_failed",
        target_id: targetId,
        target_name: result.targetName,
        scan_job_id: job.id,
      },
      dedup_key: `scan_failed:${job.id}`,
    }, { dedup_key: `scan_failed:${job.id}` });
  }

  return { claimed: jobs.length, completed, failed, alertsEnqueued };
}

/**
 * Run a scan right now (the /scan command) and report the results in chat.
 *
 * Only the passive phase runs inline: certificate transparency + DNS records,
 * which are third-party API calls that answer in seconds. The heavy phases
 * (wordlist bruteforce, host probing, JavaScript analysis, CVE matching,
 * wordlist fuzzing) stay on the cron — running them in the webhook invocation
 * blows the Workers free-tier wall-clock and CPU budget, which is what used to
 * leave /scan silent after its "started" message.
 *
 * Delivery contract for the alerts this pass produced:
 *   * the first INLINE_ALERT_LIMIT are printed straight into the chat;
 *   * every alert actually printed is baseline-recorded, so the cron does not
 *     repeat it;
 *   * anything NOT printed is enqueued as a notification job instead — it is
 *     never marked as delivered without having been delivered. (Recording an
 *     unsent alert as sent is what silently swallowed new subdomains before.)
 */
export async function runInitialScanInline(env: Env, targetId: string, chatId: number): Promise<void> {
  const target = await getTargetById(env.DB, targetId);
  if (!target) {
    await sendMessage(env, chatId, "Target not found.");
    return;
  }

  // Send before touching D1: a failed scan-row insert must never eat the
  // acknowledgement, or the operator is left with a started-but-silent scan.
  await sendMessage(
    env, chatId,
    `🟢 <b>Scanning ${escapeHtml(target.name)}…</b>\n\n` +
    `Querying certificate-transparency logs and DNS records now — results ` +
    `below in a few seconds. Live hosts, technologies, CVEs, JavaScript and ` +
    `sensitive-path fuzzing continue in the background and notify you as they land.`,
    { parseMode: "HTML" },
  );

  const scanId = `scan_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  try {
    await env.DB
      .prepare(
        `INSERT INTO scans (id, organization_id, target_id, trigger, status, requested_by, started_at, created_at, updated_at)
         VALUES (?, ?, ?, 'manual', 'running', ?, ?, ?, ?)`,
      )
      .bind(scanId, target.organization_id, targetId, String(chatId), now, now, now)
      .run();
  } catch (err) {
    // The scan itself is still worth running — only the history row is lost.
    log.warn("scan.inline_row_failed", { targetId, err: String(err) });
  }

  const result = await runScanForTarget(env, targetId, {
    trigger: "manual", scanId, phases: "passive", deadlineMs: INLINE_SCAN_BUDGET_MS,
  });

  if (!result.ok) {
    await updateScanRow(env.DB, scanId, "failed", { stop_reason: result.error ?? "unknown error" });
    await sendMessage(
      env, chatId,
      `❌ Scan of ${escapeHtml(target.name)} failed: ${escapeHtml(result.error ?? "unknown error")}`,
    );
    return;
  }

  await updateScanRow(env.DB, scanId, "completed", {
    stats: result.stats,
    stop_reason: "passive phase — full pass continues on the cron schedule",
  });
  await sendMessage(env, chatId, summaryMessage(result, true), { parseMode: "HTML" });

  const inlineSent = await deliverInlineAlerts(env, result, chatId);

  // Hand the heavy phases to the next cron tick.
  //
  // A manual scan writes a `scans` row, and that row is exactly what
  // `enqueueDueScans` throttles on — so without this the target would sit idle
  // until the 30-minute rescan window reopened, even though the operator just
  // asked for the work. Queueing it here means probing, JavaScript, CVE
  // matching and fuzzing start within one tick and notify as they land.
  await enqueueFollowUpFullScan(env, target, chatId);

  log.info("scan.inline_complete", {
    targetId, chatId, alerts: result.alerts.length, inlineSent,
  });
}

/**
 * Queue a full scan pass for the next cron tick after an inline /scan.
 *
 * Priority 2 puts it ahead of the cron-generated priority-1 rescan jobs, so the
 * operator's own request is the first thing the next tick picks up.
 */
async function enqueueFollowUpFullScan(
  env: Env,
  target: { id: string; name: string; organization_id: string },
  chatId: number,
): Promise<void> {
  const scanId = `scan_${crypto.randomUUID()}`;
  const stamp = new Date().toISOString();
  try {
    await env.DB
      .prepare(
        `INSERT INTO scans (id, organization_id, target_id, trigger, status, requested_by, created_at, updated_at)
         VALUES (?, ?, ?, 'continuation', 'queued', ?, ?, ?)`,
      )
      .bind(scanId, target.organization_id, target.id, String(chatId), stamp, stamp)
      .run();

    await enqueueJob(env.DB, "scan", {
      job_id: scanId,
      scan_id: scanId,
      target_id: target.id,
      target_name: target.name,
      organization_id: target.organization_id,
      profile: "full",
      triggered_by: "continuation",
      triggered_by_user_id: String(chatId),
      enqueued_at: stamp,
    }, { priority: 2, dedup_key: `scan_followup:${target.id}:${scanId}` });
  } catch (err) {
    // The inline results are already delivered; the background pass is a
    // bonus, and the normal 30-minute rescan still covers the target.
    log.warn("scan.followup_failed", { targetId: target.id, err: String(err) });
  }
}

/**
 * Print the first INLINE_ALERT_LIMIT alerts into the chat, baseline the ones
 * actually delivered, and enqueue everything past the limit. Returns how many
 * were printed.
 *
 * Exported for tests: the regression this guards is silent — a delivery bug
 * here loses findings without any error surfacing anywhere.
 *
 * The already-sent lookup runs only over the candidates we would actually
 * print — a popular domain's CT pass can return hundreds of names, and one D1
 * read per name would dominate the webhook invocation. The overflow needs no
 * pre-check: enqueueJob dedupes on dedup_key and the dispatcher re-checks the
 * notifications table before sending, so it can never double-report.
 */
export async function deliverInlineAlerts(env: Env, result: ScanRunResult, chatId: number): Promise<number> {
  if (result.alerts.length === 0) return 0;

  // High/critical first — if the limit cuts the list short, the urgent findings
  // are the ones that survive it.
  const ranked = [...result.alerts].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const candidates = ranked.slice(0, INLINE_ALERT_LIMIT);
  const overflow = ranked.slice(INLINE_ALERT_LIMIT);

  let delivered = 0;
  for (const alert of candidates) {
    if (await notificationAlreadySent(env.DB, alert.dedup_key)) continue;
    await sendMessage(env, chatId, inlineAlertMessage(alert), { parseMode: "HTML" });
    await recordNotificationSent(env.DB, alert, result.targetId, result.organizationId, `chat:${chatId}`);
    delivered++;
  }

  // The overflow is NOT marked as sent — it rides the queue to the same chat.
  if (overflow.length > 0) {
    await enqueueAlertNotifications(env, { ...result, alerts: overflow });
  }

  return delivered;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, informational: 0,
};

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity] ?? 0;
}

// ---------------------------------------------------------------------------
// Message formatting (inline /scan path)
// ---------------------------------------------------------------------------

const INLINE_SEVERITY_EMOJI: Record<string, string> = {
  critical: "🚨",
  high: "⚠️",
  medium: "📋",
  low: "ℹ️",
  informational: "📌",
};

/**
 * Render the end-of-pass summary.
 *
 * `passiveOnly` is passed explicitly rather than inferred from the counters: a
 * full pass that hit its wall-clock deadline before probing anything would
 * otherwise render as a discovery pass and hide the fact that it was cut short.
 */
function summaryMessage(result: ScanRunResult, passiveOnly: boolean): string {
  const s = result.stats;

  // A passive-only run reports the CT/DNS phase on its own; printing rows of
  // zeros for probes/tech/CVEs/fuzzing would read like a failed scan.
  const lines = passiveOnly
    ? [
      `✅ <b>Discovery pass finished — ${escapeHtml(result.targetName)}</b>`,
      "",
      `🌐 New subdomains: <b>${s.subdomainsFound}</b>`,
      `🗜 Certificates and DNS records: <b>${s.certsFound}</b> new certs · <b>${s.dnsRecordsFound}</b> new records`,
      `🚫 Out-of-scope results ignored: <b>${s.outOfScope}</b>`,
    ]
    : [
      `✅ <b>Scan pass finished — ${escapeHtml(result.targetName)}</b>`,
      "",
      `🌐 New subdomains: <b>${s.subdomainsFound}</b>`,
      `🖥 Live hosts probed: <b>${s.liveHosts}</b> / ${s.hostsProbed}`,
      `🔌 Ports: <b>${s.portsOpen}</b> open / ${s.portsProbed} probed this pass`,
      `🧬 New technologies: <b>${s.newTechs}</b>`,
      `🛡 CVE matches: <b>${s.cvesFound}</b>`,
      `🔑 Secret candidates: <b>${s.secretsFound}</b>`,
      `🧪 Fuzz findings: <b>${s.fuzzFindings}</b> (${s.fuzzRequests} requests)`,
    ];

  if (s.bruteforce) {
    lines.push(
      `🔁 Subdomain bruteforce: ${s.bruteforce.cursor}/${s.bruteforce.total}` +
      ` entries${s.bruteforce.done ? " (cycle complete)" : ""}`,
    );
    if (s.wildcardSkipped > 0) {
      lines.push(`🃏 Wildcard-DNS false positives filtered: <b>${s.wildcardSkipped}</b>`);
    }
  }

  if (s.topSubdomains.length > 0) {
    lines.push("", "<b>🆕 New subdomains</b>");
    for (const host of s.topSubdomains) lines.push(`• <code>${escapeHtml(host)}</code>`);
  }

  if (s.errors.length > 0) {
    lines.push("", "<b>⚠️ Provider issues</b>");
    for (const err of [...new Set(s.errors)].slice(0, 5)) {
      lines.push(`• ${escapeHtml(err.slice(0, 200))}`);
    }
  }

  if (passiveOnly) {
    lines.push(
      "",
      "<i>Live hosts, technologies, CVEs, JavaScript and sensitive-path " +
      "fuzzing run in the background — you get a message for each new one.</i>",
    );
  } else if (s.deadlineReached) {
    lines.push("", "<i>Time budget reached — probes, JavaScript and fuzzing continue on the next tick.</i>");
  }

  lines.push(
    "",
    "<i>Continuous monitoring is on. From now on you only get messages for NEW findings.</i>",
  );
  return lines.join("\n");
}

function inlineAlertMessage(alert: Alert): string {
  const emoji = INLINE_SEVERITY_EMOJI[alert.severity] ?? "📌";
  return (
    `${emoji} <b>[${alert.severity.toUpperCase()}] ${escapeHtml(alert.title)}</b>\n\n` +
    escapeHtml(alert.summary)
  );
}


async function enqueueAlertNotifications(env: Env, result: ScanRunResult): Promise<number> {
  let enqueued = 0;
  for (const alert of result.alerts) {
    await enqueueJob(env.DB, "notification", {
      organization_id: result.organizationId,
      target_id: result.targetId,
      finding_id: (alert.metadata["finding_id"] as string | undefined) ?? null,
      channel: "telegram",
      severity: alert.severity,
      payload: {
        title: alert.title,
        summary: alert.summary,
        change_type: alert.type,
        target_id: result.targetId,
        target_name: result.targetName,
        ...alert.metadata,
      },
      dedup_key: alert.dedup_key,
    }, { dedup_key: alert.dedup_key });
    enqueued++;
  }
  return enqueued;
}






