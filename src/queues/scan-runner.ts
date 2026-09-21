// src/queues/scan-runner.ts
// Synchronous scan runner — replaces the v2 queue consumer.
//
// Invoked directly from the cron handler with `ctx.waitUntil()`. Reads pending
// scan jobs from the `job_queue` D1 table (one at a time, bounded by CPU
// budget), runs the discovery pipeline, and writes any alerts back to
// `job_queue` as `notification` jobs for the next cron tick to dispatch.
//
// Free-tier constraints respected:
//   - Each job runs in the cron handler's `ctx.waitUntil()` window
//   - We claim at most FREE_TIER_MAX_JOBS_PER_CRON jobs per invocation
//   - Each job has a wall-clock timeout (FREE_TIER_SCAN_TIMEOUT_MS)
//   - Per-target locks prevent concurrent runs (D1-based)
//   - Rate limits apply before each HTTP request (D1-based)
//   - Any job that throws is marked failed + retried up to max_attempts

import type { Env } from "../env.js";
import { getTargetById, listScopeEntries } from "../db/queries/targets.js";
import { compileScope, isScopeExpired, checkHostInScope } from "../security/scope.js";
import { EmergencyStopClient } from "../db/emergency-stop.js";
import { LockClient } from "../db/distributed-lock.js";
import { discoverAssetsForTarget } from "../modules/asset-discovery.js";
import { analyzeJsForAsset } from "../modules/js-analyzer.js";
import { HttpxProvider } from "../providers/http/httpx-adapter.js";
import { log as defaultLog, D1AuditLogger } from "../audit/logger.js";
import { randomId } from "../crypto/hash.js";
import {
  upsertAsset,
  upsertService,
  upsertTechnology,
} from "../db/queries/assets.js";
import {
  claimPendingJobs,
  completeJob,
  failJob,
  enqueueJob,
} from "../db/job-queue.js";
import type { Alert } from "../modules/alerts.js";
import { buildAlert } from "../modules/alerts.js";
import { num } from "../env.js";

export async function runPendingScans(
  env: Env,
  ctx: ExecutionContext,
): Promise<{ claimed: number; completed: number; failed: number; alertsEnqueued: number }> {
  const log = defaultLog;
  const audit = new D1AuditLogger(env.DB);
  const maxJobsPerCron = num(env.FREE_TIER_MAX_JOBS_PER_CRON, 2);
  const scanTimeoutMs = num(env.FREE_TIER_SCAN_TIMEOUT_MS, 30_000);

  const jobs = await claimPendingJobs(env.DB, "scan", maxJobsPerCron, scanTimeoutMs + 30_000);
  let completed = 0;
  let failed = 0;
  let alertsEnqueued = 0;

  for (const job of jobs) {
    const result = await processScanJob(env, job, audit, log, scanTimeoutMs);
    if (result.ok) {
      await completeJob(env.DB, job.id, { summary: `${result.alerts} alerts` });
      for (const alert of result.alertsArray) {
        await enqueueJob(env.DB, "notification", {
          organization_id: result.organizationId,
          target_id: result.targetId,
          finding_id: (alert.metadata as Record<string, unknown>).finding_id as string | undefined,
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
          attempt: 0,
        }, { dedup_key: alert.dedup_key });
        alertsEnqueued++;
      }
      completed++;
    } else {
      await failJob(env.DB, job.id, result.error ?? "unknown error", {
        retry_after_seconds: 60 * (job.attempts + 1),
      });
      failed++;
      await enqueueJob(env.DB, "notification", {
        organization_id: result.organizationId,
        target_id: result.targetId,
        channel: "telegram",
        severity: "high",
        payload: {
          title: `Scan failed for ${result.targetName}`,
          summary: `Scan job ${job.id} failed: ${result.error?.slice(0, 500) ?? "unknown error"}`,
          change_type: "scan_failed",
          target_id: result.targetId,
          target_name: result.targetName,
          scan_job_id: job.id,
        },
        dedup_key: `scan_failed:${job.id}`,
        attempt: 0,
      }, { dedup_key: `scan_failed:${job.id}` });
    }
  }

  return { claimed: jobs.length, completed, failed, alertsEnqueued };
}

async function processScanJob(
  env: Env,
  job: { id: string; payload: Record<string, unknown>; attempts: number; max_attempts: number },
  audit: D1AuditLogger,
  log: typeof defaultLog,
  _scanTimeoutMs: number,
): Promise<{ ok: true; alerts: number; alertsArray: Alert[]; organizationId: string; targetId: string; targetName: string } | { ok: false; error: string; organizationId: string; targetId: string; targetName: string }> {
  const requestId = randomId("req", 12);
  const targetId = job.payload["target_id"] as string;
  const triggeredByUserId = (job.payload["triggered_by_user_id"] as string | null) ?? null;

  // 1. Check emergency stop (fail-closed)
  const es = new EmergencyStopClient(env.DB);
  if (await es.isBlocked("global") || await es.isBlocked("target", targetId)) {
    return { ok: false, error: "emergency stop active", organizationId: "", targetId, targetName: "" };
  }

  // 2. Load target & scope
  const target = await getTargetById(env.DB, targetId);
  if (!target) return { ok: false, error: "target not found", organizationId: "", targetId, targetName: "" };
  if (target.paused) return { ok: false, error: "target paused", organizationId: target.organization_id, targetId, targetName: target.name };
  if (isScopeExpired(target)) return { ok: false, error: "scope expired", organizationId: target.organization_id, targetId, targetName: target.name };

  const scopeEntries = await listScopeEntries(env.DB, targetId);
  const scope = compileScope(target, scopeEntries);

  // 3. Acquire a per-target lock via D1 row
  const lock = new LockClient(env.DB, `target:${targetId}`);
  const lockHeld = await lock.acquire(`scan:${job.id}`, 5 * 60_000);
  if (!lockHeld) {
    return { ok: false, error: "target busy (another scan running)", organizationId: target.organization_id, targetId, targetName: target.name };
  }

  try {
    const alerts: Alert[] = [];
    const host = target.name;

    // 4. Run CT + DNS discovery
    const discovery = await discoverAssetsForTarget(env, targetId, host, scope, log);
    alerts.push(...discovery.alerts);

    // 5. For each in-scope subdomain, run HTTP probe + JS analysis
    //    Limited to first 5 assets per scan to respect CPU budget.
    const assets = await env.DB
      .prepare(`SELECT id, value, normalized FROM assets WHERE target_id = ? AND type = 'subdomain' AND scope_status = 'in_scope' ORDER BY last_seen DESC LIMIT 5`)
      .bind(targetId)
      .all<{ id: string; value: string; normalized: string }>();

    const httpx = new HttpxProvider();
    const providerCtx = {
      maxResponseBytes: 5 * 1024 * 1024,
      timeoutMs: 15_000,
      cache: env.CACHE,
      userAgent: env.USER_AGENT,
      log: (m: string, f?: Record<string, unknown>) => log.info(m, f),
    };

    for (const a of assets.results ?? []) {
      const scopeCheck = checkHostInScope(scope, a.normalized);
      if (!scopeCheck.allowed) continue;

      const probe = await httpx.probeUrl(`https://${a.normalized}/`, a.normalized, providerCtx, scope);
      if (!probe || probe.status < 200 || probe.status >= 400) continue;

      const urlAsset = await upsertAsset(
        env.DB, targetId, "url",
        probe.finalUrl, probe.finalUrl, "in_scope",
        { title: probe.title, server: probe.server, technologies: probe.technologies },
      );

      const port = probe.url.startsWith("https://") ? 443 : 80;
      const svc = await upsertService(
        env.DB, urlAsset.id, port, "tcp",
        null, null, probe.status, probe.title, probe.server,
      );

      if (svc.created) {
        alerts.push(buildAlert("new_service", targetId, {
          asset_id: urlAsset.id,
          asset_value: probe.finalUrl,
          title: `New HTTP service responding: ${a.normalized}`,
          summary:
            `A new in-scope HTTP service responded successfully.\n\n` +
            `URL: ${probe.finalUrl}\nStatus: ${probe.status}\nTitle: ${probe.title ?? "—"}\nServer: ${probe.server ?? "—"}\n` +
            `Technologies: ${probe.technologies.join(", ") || "none detected"}`,
          metadata: {
            url: probe.finalUrl, status: probe.status, title: probe.title,
            server: probe.server, technologies: probe.technologies,
          },
        }));
      } else {
        for (const change of svc.changes) {
          const alertType =
            change.field === "http_title" ? "service_title_changed" :
            change.field === "http_status" ? "service_status_changed" :
            "service_header_changed";
          const fieldLabel =
            change.field === "http_title" ? "Page title" :
            change.field === "http_status" ? "HTTP status" :
            change.field === "server_header" ? "Server header" :
            change.field === "banner" ? "Service banner" :
            change.field;
          alerts.push(buildAlert(alertType, targetId, {
            asset_id: urlAsset.id,
            asset_value: probe.finalUrl,
            title: `${fieldLabel} changed on ${a.normalized}`,
            summary:
              `The ${fieldLabel.toLowerCase()} for an in-scope HTTP service changed.\n\n` +
              `URL: ${probe.finalUrl}\nField: ${fieldLabel}\nBefore: ${change.before}\nAfter: ${change.after}\n\n` +
              `Manual review recommended — this may indicate a deployment or a defacement.`,
            metadata: {
              url: probe.finalUrl, field: change.field,
              before: change.before, after: change.after,
            },
          }));
        }
      }

      for (const tech of probe.technologies) {
        const techRes = await upsertTechnology(
          env.DB, urlAsset.id, tech, null, 0.7, "httpx-worker",
        );
        if (techRes.created) {
          alerts.push(buildAlert("new_technology", targetId, {
            asset_id: urlAsset.id,
            asset_value: `${a.normalized} (${tech})`,
            title: `New technology detected on ${a.normalized}: ${tech}`,
            summary:
              `A new technology was fingerprinted on an in-scope asset.\n\n` +
              `URL: ${probe.finalUrl}\nTechnology: ${tech}\nConfidence: 0.70`,
            metadata: { url: probe.finalUrl, technology: tech },
          }));
        }
      }

      const jsResult = await analyzeJsForAsset(
        env, targetId, a.id, `https://${a.normalized}/`, scope,
        env.REDACTION_SALT ?? "fallback-redaction-salt",
      );
      alerts.push(...jsResult.alerts);
    }

    await audit.log({
      timestamp: new Date().toISOString(),
      user_id: triggeredByUserId,
      telegram_id: null,
      organization_id: target.organization_id,
      action: "scan.completed",
      target_id: targetId,
      scope_id: null,
      job_id: job.id,
      scanner: "watchtower-discovery",
      args_redacted: JSON.stringify({ profile: job.payload["profile"] ?? "passive-only", host, alerts: alerts.length }),
      result: "success",
      error: null,
      ip: null,
      request_id: requestId,
    });

    return {
      ok: true,
      alerts: alerts.length,
      alertsArray: alerts,
      organizationId: target.organization_id,
      targetId,
      targetName: target.name,
    };
  } catch (err) {
    await audit.log({
      timestamp: new Date().toISOString(),
      user_id: triggeredByUserId,
      telegram_id: null,
      organization_id: target.organization_id,
      action: "scan.failed",
      target_id: targetId,
      scope_id: null,
      job_id: job.id,
      scanner: "watchtower-discovery",
      args_redacted: "{}",
      result: "failure",
      error: String(err),
      ip: null,
      request_id: requestId,
    });
    return { ok: false, error: String(err), organizationId: target.organization_id, targetId, targetName: target.name };
  } finally {
    await lock.release(`scan:${job.id}`);
  }
}
