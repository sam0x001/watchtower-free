// src/providers/scanners/index.ts
// Adapters for each external scanner. Each one builds a RunnerJobRequest and
// delegates execution to the external runner. They never run locally.

import type { Env } from "../../env.js";
import { signJobPayload, validateToolArgs, type RunnerJobRequest } from "./runner-protocol.js";
import { sha256 } from "../../crypto/hash.js";
import { randomId } from "../../crypto/hash.js";

export interface ScannerRunnerOpts {
  env: Env;
  scanJobId: string;
  targetId: string;
  maxRuntimeSeconds?: number;
  maxOutputBytes?: number;
}

async function dispatchToRunner(opts: ScannerRunnerOpts, tool: string, args: Record<string, string | number | boolean | string[]>, scopeFingerprint: string): Promise<{ job_id: string; runner_url: string }> {
  const validation = validateToolArgs(tool, args);
  if (!validation.ok) {
    throw new Error(`Tool args rejected: ${validation.reason}`);
  }
  const payload: RunnerJobRequest = {
    scan_job_id: opts.scanJobId,
    target_id: opts.targetId,
    tool,
    args,
    scope_fingerprint: scopeFingerprint,
    max_runtime_seconds: opts.maxRuntimeSeconds ?? 600,
    max_output_bytes: opts.maxOutputBytes ?? 5 * 1024 * 1024,
  };
  const signed = await signJobPayload(payload, opts.env.API_HMAC_KEY);
  // Persist the job for the runner to fetch
  await opts.env.DB
    .prepare(`INSERT INTO scan_jobs (id, organization_id, target_id, scan_id, job_type, adapter, runner_required, priority, status, attempt, max_attempts, payload, payload_hash, requested_targets, scheduled_for, timeout_at, result_summary, created_at, updated_at) VALUES (?, (SELECT organization_id FROM targets WHERE id = ?), ?, ?, 'scan', ?, 1, 5, 'queued', 0, 3, ?, ?, '[]', ?, ?, '{}', ?, ?)`)
    .bind(signed.job_id, opts.targetId, opts.targetId, opts.scanJobId, tool, JSON.stringify(args), await sha256(JSON.stringify(args)), new Date().toISOString(), new Date(Date.now() + 3600000).toISOString(), new Date().toISOString(), new Date().toISOString())
    .run();
  return { job_id: signed.job_id, runner_url: `runner://pending/${signed.job_id}` };
}

export async function runNmap(opts: ScannerRunnerOpts, target: string, ports: string): Promise<void> {
  await dispatchToRunner(opts, "nmap", { "-p": ports, "-sV": true, "-sT": true, "--open": true, "-Pn": true }, await sha256(target));
}

export async function runSubfinder(opts: ScannerRunnerOpts, domain: string): Promise<void> {
  await dispatchToRunner(opts, "subfinder", { "-d": domain, "-all": true, "-recursive": true, "-silent": true }, await sha256(domain));
}

export async function runAmass(opts: ScannerRunnerOpts, domain: string): Promise<void> {
  await dispatchToRunner(opts, "amass", { "enum": "enum", "-d": domain, "-passive": true, "-norecursive": false }, await sha256(domain));
}

export async function runHttpx(opts: ScannerRunnerOpts, url: string): Promise<void> {
  await dispatchToRunner(opts, "httpx", { "-u": url, "-status-code": true, "-title": true, "-tech-detect": true, "-follow-redirects": false, "-timeout": 15 }, await sha256(url));
}

export async function runNuclei(opts: ScannerRunnerOpts, url: string, templates: string[], severity: string[]): Promise<void> {
  await dispatchToRunner(opts, "nuclei", { "-u": url, "-t": templates, "-severity": severity, "-rate-limit": 30, "-json": true, "-silent": true, "-timeout": 15 }, await sha256(url));
}

export async function runZap(opts: ScannerRunnerOpts, url: string): Promise<void> {
  await dispatchToRunner(opts, "zap", { "-cmd": true, "-quickurl": url, "-quickprogress": true }, await sha256(url));
}

export async function runBurp(opts: ScannerRunnerOpts, target: string, configPath: string): Promise<void> {
  await dispatchToRunner(opts, "burp", { "--target": target, "--config": configPath, "--output": "burp-report.json", "--format": "json" }, await sha256(target));
}
