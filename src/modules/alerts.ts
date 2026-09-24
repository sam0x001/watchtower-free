// src/modules/alerts.ts
// Unified alert type used across the scan pipeline. Every discovery stage
// (CT, DNS bruteforce, HTTP probing, JS analysis, secret detection, CVE
// matching, wordlist fuzzing) emits `Alert` objects. The scan runner converts
// each one into a `notification` job; the dispatcher sends it to Telegram.
//
// Dedup keys are deterministic per (alert_type, target_id, asset_identifier)
// so re-running the same scan doesn't spam the operator with duplicate alerts.

import type { Severity } from "../types.js";

export type AlertType =
  | "new_subdomain"
  | "new_ip"
  | "new_certificate"
  | "new_dns_record"
  | "new_service"
  | "new_technology"
  | "technology_version_changed"
  | "service_title_changed"
  | "service_status_changed"
  | "service_header_changed"
  | "new_javascript_file"
  | "javascript_changed"
  | "new_api_endpoint"
  | "new_fuzz_endpoint"
  | "new_secret_candidate"
  | "new_cve"
  | "scan_completed"
  | "scan_failed";

export interface Alert {
  type: AlertType;
  severity: Severity;
  title: string;
  summary: string;
  /** Stable identifier used as the notification dedup_key. */
  dedup_key: string;
  /** Free-form metadata that ends up in the notification payload. */
  metadata: Record<string, unknown>;
}

/** Helper: assign a severity for a given alert type. */
export function severityFor(type: AlertType): Severity {
  switch (type) {
    case "new_secret_candidate":
      return "high";
    case "new_cve":
    case "new_certificate":
      return "high";
    case "new_subdomain":
    case "new_ip":
    case "new_service":
    case "new_api_endpoint":
    case "new_fuzz_endpoint":
    case "new_javascript_file":
    case "technology_version_changed":
    case "service_status_changed":
      return "medium";
    case "javascript_changed":
    case "service_title_changed":
    case "service_header_changed":
    case "new_technology":
    case "new_dns_record":
      return "low";
    case "scan_completed":
    case "scan_failed":
    default:
      return "informational";
  }
}

export function buildAlert(
  type: AlertType,
  targetId: string,
  fields: {
    asset_id?: string;
    asset_value: string;       // the asset the alert concerns (hostname, URL, IP)
    title: string;
    summary: string;
    metadata?: Record<string, unknown>;
  },
  severity?: Severity,
): Alert {
  const sev = severity ?? severityFor(type);
  // dedup_key format: "<type>:<target_id>:<asset_value>"
  // For the same asset discovered again on a later scan, the dedup_key matches
  // and the dispatcher suppresses the duplicate.
  const dedup_key = `${type}:${targetId}:${fields.asset_value}`;
  return {
    type,
    severity: sev,
    title: fields.title,
    summary: fields.summary,
    dedup_key,
    metadata: {
      target_id: targetId,
      asset_id: fields.asset_id ?? null,
      asset_value: fields.asset_value,
      alert_type: type,
      ...fields.metadata,
    },
  };
}
