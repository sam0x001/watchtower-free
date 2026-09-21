// src/providers/scanners/runner-protocol.ts
// External scanner runner protocol.
//
// Workers cannot run nmap/nuclei/etc. directly. Instead, an external runner
// (container, GitHub Action, Cloud Run, Fly.io, Lambda) registers with the
// bot, polls the Worker for jobs, executes them in a sandboxed environment
// with allowlisted tools, and posts signed results back.
//
// Job payloads are HMAC-signed with `API_HMAC_KEY`. Runners verify the
// signature before executing. Result payloads are similarly signed.

import type { RunnerJobPayload } from "../../types.js";
import { hmacSha256 } from "../../crypto/hash.js";
import { constantTimeEqual } from "../../crypto/hash.js";
import { randomId } from "../../crypto/hash.js";

export interface RunnerJobRequest {
  scan_job_id: string;
  target_id: string;
  tool: string;        // "nmap" | "subfinder" | "amass" | "httpx" | "nuclei" | "zap" | "burp"
  args: Record<string, string | number | boolean | string[]>;
  scope_fingerprint: string;
  max_runtime_seconds: number;
  max_output_bytes: number;
}

export async function signJobPayload(payload: RunnerJobRequest, apiHmacKey: string): Promise<RunnerJobPayload> {
  const now = new Date();
  const expires_at = new Date(now.getTime() + 30 * 60 * 1000).toISOString(); // 30-min validity
  const base: Omit<RunnerJobPayload, "signature"> = {
    job_id: randomId("job", 12),
    scan_job_id: payload.scan_job_id,
    target_id: payload.target_id,
    tool: payload.tool,
    args: payload.args,
    scope_fingerprint: payload.scope_fingerprint,
    max_runtime_seconds: payload.max_runtime_seconds,
    max_output_bytes: payload.max_output_bytes,
    created_at: now.toISOString(),
    expires_at,
  };
  const signature = await hmacSha256(apiHmacKey, JSON.stringify(base));
  return { ...base, signature };
}

export async function verifyJobPayload(payload: RunnerJobPayload, apiHmacKey: string): Promise<boolean> {
  if (!payload.signature) return false;
  // Reject expired
  if (new Date(payload.expires_at).getTime() < Date.now()) return false;
  const { signature, ...rest } = payload;
  const expected = await hmacSha256(apiHmacKey, JSON.stringify(rest));
  return constantTimeEqual(signature, expected);
}

export interface RunnerResultPayload {
  job_id: string;
  scan_job_id: string;
  status: "completed" | "failed" | "timeout" | "cancelled";
  tool: string;
  stdout_b64?: string;  // base64, capped at max_output_bytes
  stderr_b64?: string;
  exit_code: number;
  duration_seconds: number;
  artifacts: { filename: string; sha256: string; size_bytes: number }[];
  scope_validation_passed: boolean;
  timestamp: string;
  signature: string;
}

export async function signResultPayload(
  payload: Omit<RunnerResultPayload, "signature">,
  apiHmacKey: string,
): Promise<RunnerResultPayload> {
  const signature = await hmacSha256(apiHmacKey, JSON.stringify(payload));
  return { ...payload, signature };
}

export async function verifyResultPayload(
  payload: RunnerResultPayload,
  apiHmacKey: string,
): Promise<boolean> {
  if (!payload.signature) return false;
  if (new Date(payload.timestamp).getTime() < Date.now() - 60 * 60 * 1000) return false; // 1h skew
  const { signature, ...rest } = payload;
  const expected = await hmacSha256(apiHmacKey, JSON.stringify(rest));
  return constantTimeEqual(signature, expected);
}

/**
 * The list of tool names a runner is allowed to execute. ANY other name MUST
 * be rejected. Arguments are also constrained per-tool (see allowlist below).
 */
export const ALLOWED_TOOLS = new Set([
  "nmap", "subfinder", "amass", "httpx", "nuclei", "zap", "burp",
]);

export interface ToolArgSpec {
  // Arguments the tool accepts. Anything else is rejected.
  allowedFlags: Set<string>;
  // If true, the tool may produce non-trivial network egress.
  networkEgress: boolean;
  maxRuntimeSeconds: number;
  maxOutputBytes: number;
}

export const TOOL_ARG_SPECS: Record<string, ToolArgSpec> = {
  nmap: {
    allowedFlags: new Set(["-sV", "-sT", "-p", "--top-ports", "--open", "-Pn", "-T3", "--version-intensity", "-"]),
    networkEgress: true,
    maxRuntimeSeconds: 600,
    maxOutputBytes: 2 * 1024 * 1024,
  },
  subfinder: {
    allowedFlags: new Set(["-d", "-all", "-recursive", "-silent", "-timeout", "-sources"]),
    networkEgress: true,
    maxRuntimeSeconds: 300,
    maxOutputBytes: 1 * 1024 * 1024,
  },
  amass: {
    allowedFlags: new Set(["enum", "-d", "-passive", "-noalts", "-norecursive", "-timeout"]),
    networkEgress: true,
    maxRuntimeSeconds: 300,
    maxOutputBytes: 1 * 1024 * 1024,
  },
  httpx: {
    allowedFlags: new Set(["-u", "-status-code", "-title", "-tech-detect", "-follow-redirects", "-timeout", "-threads"]),
    networkEgress: true,
    maxRuntimeSeconds: 300,
    maxOutputBytes: 2 * 1024 * 1024,
  },
  nuclei: {
    allowedFlags: new Set(["-u", "-t", "-severity", "-tags", "-timeout", "-rate-limit", "-bulk-size", "-no-color", "-json", "-silent"]),
    networkEgress: true,
    maxRuntimeSeconds: 600,
    maxOutputBytes: 5 * 1024 * 1024,
  },
  zap: {
    allowedFlags: new Set(["-cmd", "-quickurl", "-quickprogress", "-quickout", "-port"]),
    networkEgress: true,
    maxRuntimeSeconds: 1200,
    maxOutputBytes: 5 * 1024 * 1024,
  },
  burp: {
    allowedFlags: new Set(["--target", "--config", "--output", "--format"]),
    networkEgress: true,
    maxRuntimeSeconds: 1200,
    maxOutputBytes: 5 * 1024 * 1024,
  },
};

/**
 * Validates that a runner-supplied args dict only contains allowed flags and
 * safe values. NEVER allow arbitrary strings to be concatenated into a shell
 * command. Runners MUST invoke tools using execve-style argument arrays, not
 * shell interpolation.
 */
export function validateToolArgs(tool: string, args: Record<string, string | number | boolean | string[]>): { ok: boolean; reason?: string } {
  const spec = TOOL_ARG_SPECS[tool];
  if (!spec) return { ok: false, reason: `tool ${tool} not in allowed list` };
  for (const [key, value] of Object.entries(args)) {
    if (!spec.allowedFlags.has(key)) return { ok: false, reason: `flag ${key} not allowed for ${tool}` };
    if (typeof value === "string") {
      // No shell metacharacters
      if (/[;|&$`><\n\r]/.test(value)) return { ok: false, reason: `flag ${key} value contains shell metacharacters` };
      if (value.length > 1024) return { ok: false, reason: `flag ${key} value too long` };
    }
    if (Array.isArray(value)) {
      for (const v of value) {
        if (typeof v !== "string") return { ok: false, reason: `flag ${key} array element must be string` };
        if (/[;|&$`><\n\r]/.test(v)) return { ok: false, reason: `flag ${key} array value contains shell metacharacters` };
      }
      if (value.length > 100) return { ok: false, reason: `flag ${key} array too long` };
    }
  }
  return { ok: true };
}
