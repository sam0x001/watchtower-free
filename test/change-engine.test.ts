// test/change-engine.test.ts
import { describe, it, expect } from "vitest";
import { diffSnapshots, isVolatileKey, classifyChange, type DiffableSnapshot } from "../src/modules/change-engine.js";

describe("change detection", () => {
  it("detects added fields", () => {
    const after: DiffableSnapshot = { assetId: "a1", fields: { title: "Hello" }, capturedAt: "now" };
    const diffs = diffSnapshots(null, after);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.type).toBe("added");
    expect(diffs[0]!.path).toBe("title");
  });

  it("detects changed fields", () => {
    const before: DiffableSnapshot = { assetId: "a1", fields: { title: "Old", status: 200 }, capturedAt: "t1" };
    const after: DiffableSnapshot = { assetId: "a1", fields: { title: "New", status: 200 }, capturedAt: "t2" };
    const diffs = diffSnapshots(before, after);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.type).toBe("changed");
    expect(diffs[0]!.path).toBe("title");
  });

  it("detects removed fields", () => {
    const before: DiffableSnapshot = { assetId: "a1", fields: { title: "Hello", csrf: "abc" }, capturedAt: "t1" };
    const after: DiffableSnapshot = { assetId: "a1", fields: { title: "Hello" }, capturedAt: "t2" };
    const diffs = diffSnapshots(before, after);
    expect(diffs.some((d) => d.type === "removed" && d.path === "csrf")).toBe(true);
  });

  it("ignores volatile keys", () => {
    expect(isVolatileKey("etag")).toBe(true);
    expect(isVolatileKey("date")).toBe(true);
    expect(isVolatileKey("x-request-id")).toBe(true);
    expect(isVolatileKey("title")).toBe(false);
    expect(isVolatileKey("server")).toBe(false);
  });

  it("classifies changes by severity", () => {
    expect(classifyChange("new_vulnerability", 0.9)).toBe("critical");
    expect(classifyChange("new_subdomain", 0.95)).toBe("high");
    expect(classifyChange("dns_change", 0.9)).toBe("medium");
    expect(classifyChange("javascript_changed", 0.9)).toBe("low");
    expect(classifyChange("closed_service", 0.9)).toBe("informational");
  });
});
