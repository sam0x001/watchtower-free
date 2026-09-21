// src/modules/change-engine.ts
// Compares the latest scan result with the previous baseline and emits
// deduplicated change records. Ignores known-volatile fields.

import type { D1Database } from "@cloudflare/workers-types";
import { randomId } from "../crypto/hash.js";
import type { DiffResult } from "../types.js";

export interface ChangeRecord {
  id: string;
  organization_id: string;
  target_id: string;
  asset_id?: string;
  change_type: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  before: unknown;
  after: unknown;
  confidence: number;
  volatile: boolean;
  first_seen: string;
}

const VOLATILE_KEYS = new Set([
  "etag", "last-modified", "date", "expires", "age", "x-cache",
  "x-request-id", "x-trace-id", "x-correlation-id", "set-cookie",
  "csrf-token", "x-csrf-token", "x-amzn-trace-id", "x-amz-cf-id",
  "x-served-by", "x-timer", "x-fastly-request-id",
]);

export function isVolatileKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (VOLATILE_KEYS.has(lower)) return true;
  if (lower.startsWith("x-") && (lower.includes("id") || lower.includes("trace") || lower.includes("request"))) return true;
  return false;
}

export interface DiffableSnapshot {
  assetId: string;
  fields: Record<string, unknown>;
  capturedAt: string;
}

export function diffSnapshots(before: DiffableSnapshot | null, after: DiffableSnapshot): DiffResult[] {
  const out: DiffResult[] = [];
  if (!before) {
    for (const [k, v] of Object.entries(after.fields)) {
      if (isVolatileKey(k)) continue;
      out.push({ type: "added", path: k, before: null, after: v, confidence: 0.85, severity: null, volatile: false });
    }
    return out;
  }
  for (const [k, v] of Object.entries(after.fields)) {
    if (isVolatileKey(k)) continue;
    const prev = before.fields[k];
    if (prev === undefined) {
      out.push({ type: "added", path: k, before: null, after: v, confidence: 0.9, severity: null, volatile: false });
    } else if (!deepEqual(prev, v)) {
      out.push({ type: "changed", path: k, before: prev, after: v, confidence: 0.85, severity: null, volatile: false });
    }
  }
  for (const [k, v] of Object.entries(before.fields)) {
    if (isVolatileKey(k)) continue;
    if (after.fields[k] === undefined) {
      out.push({ type: "removed", path: k, before: v, after: null, confidence: 0.85, severity: null, volatile: false });
    }
  }
  return out;
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object" || a === null || b === null) return false;
  try {
    return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
  } catch {
    return false;
  }
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (typeof v === "object" && v !== null) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

export function classifyChange(changeType: string, confidence: number): "informational" | "low" | "medium" | "high" | "critical" {
  switch (changeType) {
    case "new_subdomain":
    case "new_certificate":
      return confidence >= 0.9 ? "high" : "medium";
    case "new_ip":
      return "medium";
    case "dns_change":
    case "tls_change":
      return "medium";
    case "new_javascript":
    case "javascript_changed":
      return "low";
    case "new_api_endpoint":
    case "api_endpoint_changed":
      return confidence >= 0.85 ? "medium" : "low";
    case "new_secret_candidate":
      return "high";
    case "technology_changed":
      return "medium";
    case "service_outage":
    case "scope_violation":
      return "high";
    case "new_vulnerability":
    case "severity_increase":
      return "critical";
    case "new_open_service":
      return "high";
    case "closed_service":
      return "informational";
    default:
      return "informational";
  }
}

export async function persistChange(db: D1Database, record: Omit<ChangeRecord, "id">): Promise<string> {
  const id = randomId("chg", 12);
  await db
    .prepare(`INSERT INTO changes (id, organization_id, target_id, asset_id, change_type, severity, before_json, after_json, confidence, volatile, first_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(
      id, record.organization_id, record.target_id, record.asset_id ?? null,
      record.change_type, record.severity,
      JSON.stringify(record.before), JSON.stringify(record.after),
      record.confidence, record.volatile ? 1 : 0,
      record.first_seen, new Date().toISOString(),
    )
    .run();
  return id;
}
