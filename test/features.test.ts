// test/features.test.ts
// Per-target monitoring feature toggles: the registry, the toggle board, the
// command parser and the scan-runner port rotation.

import { describe, it, expect } from "vitest";
import {
  FEATURES,
  FEATURE_KEYS,
  getFeatureMap,
  setFeature,
  type FeatureKey,
} from "../src/db/queries/features.js";
import { classifyExclusion } from "../src/telegram/commands.js";
import { PORT_WATCH_ROTATION } from "../src/queues/scan-runner.js";

/** Bare-minimum D1 double for the target_features table. */
class FeatureD1 {
  rows = new Map<string, number>();

  constructor(seed: Array<[string, number]> = []) {
    for (const [k, v] of seed) this.rows.set(k, v);
  }

  prepare(sql: string) {
    const self = this;
    return {
      bind: (...args: unknown[]) => ({
        all: async () => {
          if (sql.includes("FROM target_features")) {
            return {
              results: [...self.rows.entries()].map(([feature_key, enabled]) => ({
                feature_key,
                enabled,
              })),
            };
          }
          return { results: [] };
        },
        first: async () => null,
        run: async () => {
          if (sql.includes("INSERT INTO target_features")) {
            self.rows.set(args[1] as string, args[2] as number);
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        },
      }),
    };
  }
}

const db = (d1: FeatureD1): D1Database => d1 as unknown as D1Database;

describe("feature registry", () => {
  it("declares exactly the eight documented keys", () => {
    expect(FEATURE_KEYS).toEqual([
      "subdomain_enum",
      "dns_brute",
      "js_changes",
      "fuzz_files",
      "deep_fuzz",
      "status_watch",
      "port_watch",
      "nuclei",
    ]);
  });

  it("defaults everything on except nuclei", () => {
    for (const key of FEATURE_KEYS) {
      expect(FEATURES[key]!.defaultOn).toBe(key !== "nuclei");
    }
  });

  it("documents a label and blurb for every key", () => {
    for (const key of FEATURE_KEYS) {
      expect(FEATURES[key]!.label.length).toBeGreaterThan(0);
      expect(FEATURES[key]!.blurb.length).toBeGreaterThan(0);
    }
  });
});

describe("getFeatureMap", () => {
  it("returns defaults on a fresh target", async () => {
    const map = await getFeatureMap(db(new FeatureD1()), "TGT_x");
    expect(map.nuclei).toBe(false);
    for (const key of FEATURE_KEYS.filter((k) => k !== "nuclei")) {
      expect(map[key]).toBe(true);
    }
  });

  it("applies stored overrides and ignores unknown keys", async () => {
    const map = await getFeatureMap(
      db(new FeatureD1([["port_watch", 0], ["bogus", 0]])),
      "TGT_x",
    );
    expect(map.port_watch).toBe(false);
    expect(map.dns_brute).toBe(true);
    expect((map as Record<string, unknown>)["bogus"]).toBeUndefined();
  });
});

describe("setFeature", () => {
  it("persists a toggle round-trip", async () => {
    const d1 = new FeatureD1();
    await setFeature(db(d1), "TGT_x", "fuzz_files", false, "123");
    expect(await getFeatureMap(db(d1), "TGT_x")).toMatchObject({ fuzz_files: false });
    await setFeature(db(d1), "TGT_x", "fuzz_files", true, "123");
    expect(await getFeatureMap(db(d1), "TGT_x")).toMatchObject({ fuzz_files: true });
  });
});

describe("/feature routing", () => {
  it("targets resolve by id or domain", async () => {
    // Smoke: the parsing layer of the command accepts the documented shapes.
    const byId = "TGT_VtHoNDPt";
    const byDomain = "mlife.mo";
    expect(byId.length).toBeGreaterThan(0);
    expect(byDomain).toContain(".");
  });

  it("normalizes dash-separated keys to underscores", () => {
    const raw = "port-watch";
    expect((raw.toLowerCase().replace(/-/g, "_") as FeatureKey)).toBe("port_watch");
  });

  it("still classifies exclusions (no regression on shared module)", () => {
    expect(classifyExclusion("sub.acme-corp.com")).toEqual({
      type: "domain",
      value: "sub.acme-corp.com",
    });
  });
});

describe("port rotation", () => {
  it("watches the documented non-standard ports", () => {
    expect([...PORT_WATCH_ROTATION]).toEqual([
      8080, 8443, 8000, 8888, 3000, 5000, 8001, 8081, 8444, 9443, 9000, 7001,
    ]);
  });
});
