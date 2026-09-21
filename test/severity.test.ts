// test/severity.test.ts
import { describe, it, expect } from "vitest";
import { calculatePriority, cvssToSeverity, severityForChangeType, bumpSeverity } from "../src/modules/severity.js";

describe("severity calculation", () => {
  it("maps CVSS to severity", () => {
    expect(cvssToSeverity(9.5)).toBe("critical");
    expect(cvssToSeverity(7.5)).toBe("high");
    expect(cvssToSeverity(5.0)).toBe("medium");
    expect(cvssToSeverity(2.0)).toBe("low");
    expect(cvssToSeverity(0.0)).toBe("informational");
    expect(cvssToSeverity(null)).toBe("informational");
  });

  it("assigns change-type severity", () => {
    expect(severityForChangeType("new_vulnerability", 0.9)).toBe("critical");
    expect(severityForChangeType("new_secret_candidate", 0.9)).toBe("critical");
    expect(severityForChangeType("new_subdomain", 0.95)).toBe("high");
    expect(severityForChangeType("new_subdomain", 0.5)).toBe("medium");
    expect(severityForChangeType("dns_change", 0.9)).toBe("medium");
    expect(severityForChangeType("closed_service", 0.9)).toBe("informational");
  });

  it("bumps severity upward", () => {
    expect(bumpSeverity("low", "high")).toBe("high");
    expect(bumpSeverity("high", "low")).toBe("high");
    expect(bumpSeverity("informational", "critical")).toBe("critical");
  });

  it("calculates priority with all inputs", () => {
    const priority = calculatePriority({
      cvssScore: 9.5,
      epssScore: 0.8,
      isPubliclyExposed: true,
      assetCriticality: "critical",
      requiresAuthentication: "none",
      dataSensitivity: "regulated",
      availabilityImpact: "high",
      knownExploited: true,
      confidence: 0.9,
      inScope: true,
    });
    expect(priority).toBeGreaterThan(30);
  });

  it("zeros priority when out of scope", () => {
    const priority = calculatePriority({
      cvssScore: 9.5,
      epssScore: 0.9,
      isPubliclyExposed: true,
      assetCriticality: "critical",
      requiresAuthentication: "none",
      dataSensitivity: "regulated",
      availabilityImpact: "high",
      knownExploited: true,
      confidence: 1.0,
      inScope: false,
    });
    expect(priority).toBe(0);
  });

  it("discounts priority by confidence", () => {
    const high = calculatePriority({
      cvssScore: 9.0, epssScore: 0.5, isPubliclyExposed: true, assetCriticality: "high",
      requiresAuthentication: "none", dataSensitivity: "confidential", availabilityImpact: "high",
      knownExploited: false, confidence: 1.0, inScope: true,
    });
    const low = calculatePriority({
      cvssScore: 9.0, epssScore: 0.5, isPubliclyExposed: true, assetCriticality: "high",
      requiresAuthentication: "none", dataSensitivity: "confidential", availabilityImpact: "high",
      knownExploited: false, confidence: 0.3, inScope: true,
    });
    expect(low).toBeLessThan(high);
  });
});
