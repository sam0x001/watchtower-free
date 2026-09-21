// test/alerts.test.ts
// Validates the unified Alert type + dedup-key generation.

import { describe, it, expect } from "vitest";
import { buildAlert, severityFor, type AlertType } from "../src/modules/alerts.js";

describe("alert severity mapping", () => {
  it("assigns HIGH severity to secret candidates and new certificates", () => {
    expect(severityFor("new_secret_candidate")).toBe("high");
    expect(severityFor("new_certificate")).toBe("high");
  });

  it("assigns MEDIUM severity to new assets and important service changes", () => {
    expect(severityFor("new_subdomain")).toBe("medium");
    expect(severityFor("new_ip")).toBe("medium");
    expect(severityFor("new_service")).toBe("medium");
    expect(severityFor("new_api_endpoint")).toBe("medium");
    expect(severityFor("new_javascript_file")).toBe("medium");
    expect(severityFor("technology_version_changed")).toBe("medium");
    expect(severityFor("service_status_changed")).toBe("medium");
  });

  it("assigns LOW severity to content changes", () => {
    expect(severityFor("javascript_changed")).toBe("low");
    expect(severityFor("service_title_changed")).toBe("low");
    expect(severityFor("service_header_changed")).toBe("low");
    expect(severityFor("new_technology")).toBe("low");
    expect(severityFor("new_dns_record")).toBe("low");
  });

  it("assigns INFORMATIONAL severity to scan lifecycle events", () => {
    expect(severityFor("scan_completed")).toBe("informational");
    expect(severityFor("scan_failed")).toBe("informational");
  });
});

describe("alert dedup keys", () => {
  it("produces stable dedup keys for the same alert type + target + asset", () => {
    const a1 = buildAlert("new_subdomain", "TGT_1", {
      asset_value: "api.example.com",
      title: "New subdomain",
      summary: "...",
    });
    const a2 = buildAlert("new_subdomain", "TGT_1", {
      asset_value: "api.example.com",
      title: "Different title (won't affect dedup)",
      summary: "...",
    });
    expect(a1.dedup_key).toBe(a2.dedup_key);
    expect(a1.dedup_key).toBe("new_subdomain:TGT_1:api.example.com");
  });

  it("produces different dedup keys for different asset values", () => {
    const a1 = buildAlert("new_subdomain", "TGT_1", {
      asset_value: "api.example.com",
      title: "...",
      summary: "...",
    });
    const a2 = buildAlert("new_subdomain", "TGT_1", {
      asset_value: "admin.example.com",
      title: "...",
      summary: "...",
    });
    expect(a1.dedup_key).not.toBe(a2.dedup_key);
  });

  it("produces different dedup keys for different alert types on the same asset", () => {
    const a1 = buildAlert("new_javascript_file", "TGT_1", {
      asset_value: "https://example.com/app.js",
      title: "...",
      summary: "...",
    });
    const a2 = buildAlert("javascript_changed", "TGT_1", {
      asset_value: "https://example.com/app.js",
      title: "...",
      summary: "...",
    });
    expect(a1.dedup_key).not.toBe(a2.dedup_key);
  });

  it("allows caller-specified severity override", () => {
    const a = buildAlert("new_dns_record", "TGT_1", {
      asset_value: "A example.com → 1.2.3.4",
      title: "...",
      summary: "...",
    }, "critical");
    expect(a.severity).toBe("critical");
  });

  it("packs metadata for the notification payload", () => {
    const a = buildAlert("new_secret_candidate", "TGT_1", {
      asset_id: "AST_1",
      asset_value: "https://example.com/app.js:42",
      title: "Possible aws_access_key_id",
      summary: "...",
      metadata: { secret_type: "aws_access_key_id", line: 42 },
    });
    expect(a.metadata).toMatchObject({
      target_id: "TGT_1",
      asset_id: "AST_1",
      asset_value: "https://example.com/app.js:42",
      alert_type: "new_secret_candidate",
      secret_type: "aws_access_key_id",
      line: 42,
    });
  });
});

describe("alert coverage", () => {
  it("covers every alert type mentioned in the spec", () => {
    const requiredTypes: AlertType[] = [
      "new_subdomain", "new_ip", "new_certificate", "new_dns_record",
      "new_service", "new_technology", "technology_version_changed",
      "service_title_changed", "service_status_changed", "service_header_changed",
      "new_javascript_file", "javascript_changed", "new_api_endpoint",
      "new_secret_candidate", "scan_completed", "scan_failed",
    ];
    for (const t of requiredTypes) {
      expect(() => severityFor(t)).not.toThrow();
    }
  });
});
