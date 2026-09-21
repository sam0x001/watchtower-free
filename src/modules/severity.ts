// src/modules/severity.ts
// Severity calculation — combines technical severity, exploitability,
// exposure, asset criticality, business impact, auth requirement, data
// sensitivity, availability impact, known exploitation status, confidence.

import type { Finding } from "../types.js";
import type { Severity } from "../constants.js";

export interface SeverityInputs {
  cvssScore: number | null;
  epssScore: number | null;
  isPubliclyExposed: boolean;
  assetCriticality: "low" | "medium" | "high" | "critical";
  requiresAuthentication: "none" | "low" | "high";
  dataSensitivity: "public" | "internal" | "confidential" | "regulated";
  availabilityImpact: "none" | "low" | "high";
  knownExploited: boolean;
  confidence: number;
  inScope: boolean;
}

export function cvssToSeverity(score: number | null): Severity {
  if (score === null) return "informational";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "informational";
}

const SEVERITY_POINTS: Record<Severity, number> = {
  informational: 1,
  low: 3,
  medium: 6,
  high: 9,
  critical: 12,
};

export function calculatePriority(inputs: SeverityInputs): number {
  let score = 0;
  score += SEVERITY_POINTS[cvssToSeverity(inputs.cvssScore)];

  // EPSS — known exploitation probability
  if (inputs.epssScore !== null) {
    score += Math.min(5, inputs.epssScore * 5);
  }
  if (inputs.knownExploited) score += 8;

  // Public exposure
  if (inputs.isPubliclyExposed) score += 3;

  // Asset criticality
  switch (inputs.assetCriticality) {
    case "critical": score += 4; break;
    case "high": score += 2; break;
    case "medium": score += 1; break;
    case "low": break;
  }

  // Auth requirement (lower requirement = higher priority)
  switch (inputs.requiresAuthentication) {
    case "none": score += 3; break;
    case "low": score += 1; break;
    case "high": break;
  }

  // Data sensitivity
  switch (inputs.dataSensitivity) {
    case "regulated": score += 5; break;
    case "confidential": score += 3; break;
    case "internal": score += 1; break;
    case "public": break;
  }

  // Availability impact
  if (inputs.availabilityImpact === "high") score += 3;
  else if (inputs.availabilityImpact === "low") score += 1;

  // Confidence discount
  score = score * Math.max(0.3, Math.min(1.0, inputs.confidence));

  // Out-of-scope findings are always deprioritized
  if (!inputs.inScope) score = 0;

  return Math.round(score * 10) / 10;
}

export function severityForChangeType(changeType: string, confidence: number): Severity {
  switch (changeType) {
    case "new_vulnerability":
    case "severity_increase":
    case "new_secret_candidate":
      return "critical";
    case "new_subdomain":
    case "new_open_service":
    case "scope_violation":
    case "service_outage":
    case "new_certificate":
      return confidence >= 0.9 ? "high" : "medium";
    case "dns_change":
    case "tls_change":
    case "technology_changed":
    case "new_api_endpoint":
      return "medium";
    case "javascript_changed":
    case "header_changed":
    case "title_changed":
      return "low";
    case "closed_service":
    case "removed_subdomain":
      return "informational";
    default:
      return "informational";
  }
}

export function bumpSeverity(current: Severity, next: Severity): Severity {
  const order: Severity[] = ["informational", "low", "medium", "high", "critical"];
  return order.indexOf(next) > order.indexOf(current) ? next : current;
}
