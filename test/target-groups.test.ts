// test/target-groups.test.ts
// Target categories: /target_add creates a bucket, /add <domain> <category>
// assigns membership, /target_info lists members, and feature toggles stay
// strictly per domain.

import { describe, it, expect } from "vitest";
import {
  createTargetGroup,
  getTargetGroupByNameOrId,
  listTargetGroups,
  listTargetsByGroup,
  setTargetGroup,
  deleteTargetGroup,
  createTarget,
} from "../src/db/queries/targets.js";
import { loadTargetOverview, countEnabled } from "../src/db/queries/groups-view.js";
import { getFeatureMap, setFeature } from "../src/db/queries/features.js";
import type { Target, TargetGroup } from "../src/types.js";

const FEATURE_COUNT = 8;

// ---------------------------------------------------------------------------
// Minimal in-memory D1 double: target_groups + targets + scopes + scans +
// target_features + the group-view aggregates.
// ---------------------------------------------------------------------------
class GroupD1 {
  groups: Array<Record<string, unknown>> = [];
  targets: Array<Record<string, unknown>> = [];
  scopes: Array<Record<string, unknown>> = [];
  scans: Array<Record<string, unknown>> = [];
  features: Array<Record<string, unknown>> = [];

  prepare(sql: string) {
    const self = this;
    const exec = (args: unknown[]) => ({
      first: async <T>() => {
        if (sql.includes("FROM target_groups WHERE id = ?")) {
          return (self.groups.find((g) => g.id === args[0]) ?? null) as T | null;
        }
        if (sql.includes("FROM target_groups WHERE name = ?")) {
          const name = String(args[0]).toLowerCase();
          return (self.groups.find((g) => String(g.name).toLowerCase() === name) ?? null) as T | null;
        }
        if (sql.includes("SELECT * FROM targets WHERE id = ?")) {
          return (self.targets.find((t) => t.id === args[0]) ?? null) as T | null;
        }
        if (sql.includes("SELECT * FROM targets WHERE name = ?")) {
          return (self.targets.find((t) => t.name === args[0]) ?? null) as T | null;
        }
        return null;
      },
      all: async <T>() => {
          if (sql.includes("FROM target_groups ORDER BY")) {
            return { results: [...self.groups].reverse() as T[] };
          }
          if (sql.includes("FROM targets WHERE group_id = ?")) {
            return {
              results: self.targets
                .filter((t) => t.group_id === args[0])
                .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at))) as T[],
            };
          }
          if (sql.includes("FROM targets ORDER BY")) {
            return { results: [...self.targets] as T[] };
          }
          if (sql.includes("MAX(created_at)")) {
            const ids = new Set(args as string[]);
            const out: Array<{ target_id: string; last_scan: string }> = [];
            for (const id of ids) {
              const rows = self.scans.filter((s) => s.target_id === id);
              if (rows.length > 0) {
                out.push({ target_id: id, last_scan: String(rows.map((s) => s.created_at).sort().at(-1)) });
              }
            }
            return { results: out as T[] };
          }
          if (sql.includes("COUNT(*) AS n")) {
            const ids = new Set(args as string[]);
            const out: Array<{ target_id: string; n: number }> = [];
            for (const id of ids) {
              const n = self.scopes.filter(
                (s) => s.target_id === id && s.is_denylist === 1 && s.status === "active",
              ).length;
              out.push({ target_id: id, n });
            }
            return { results: out as T[] };
          }
          if (sql.includes("FROM target_features")) {
            const ids = new Set(args as string[]);
            return { results: self.features.filter((f) => ids.has(String(f.target_id))) as T[] };
          }
          return { results: [] as T[] };
        },
        run: async () => {
          if (sql.includes("INSERT INTO target_groups")) {
            self.groups.push({
              id: args[0], name: args[1], organization_id: "default",
              created_by: args[2], created_at: args[3], updated_at: args[4],
            });
            return { meta: { changes: 1 } };
          }
          if (sql.includes("INSERT INTO targets")) {
            self.targets.push({
              id: args[0], name: args[1], organization_id: "default",
              group_id: args[2], created_by: args[3],
              status: "active", created_at: args[4], updated_at: args[5],
            });
            return { meta: { changes: 1 } };
          }
          if (sql.includes("INSERT INTO scopes")) {
            self.scopes.push({
              id: `scope_${self.scopes.length + 1}`, target_id: args[1],
              is_denylist: args[5], status: "active",
            });
            return { meta: { changes: 1 } };
          }
          if (sql.includes("UPDATE targets SET group_id")) {
            const t = self.targets.find((x) => x.id === args[2]);
            if (t) t.group_id = args[0];
            return { meta: { changes: t ? 1 : 0 } };
          }
          if (sql.includes("DELETE FROM target_groups")) {
            for (const t of self.targets) if (t.group_id === args[0]) t.group_id = null;
            self.groups = self.groups.filter((g) => g.id !== args[0]);
            return { meta: { changes: 1 } };
          }
          if (sql.includes("INSERT INTO target_features")) {
            const row = self.features.find(
              (f) => f.target_id === args[0] && f.feature_key === args[1],
            );
            if (row) {
              row.enabled = args[2];
              row.updated_at = args[4];
            } else {
              self.features.push({
                target_id: args[0], feature_key: args[1], enabled: args[2],
                updated_by: args[3], updated_at: args[4],
              });
            }
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        },
    });

    // D1 allows .first/.all/.run both directly (no binds) and after .bind();
    // the double must mirror that.
    const bound = (...args: unknown[]) => exec(args);
    Object.assign(bound, exec([]));
    return { bind: bound, ...exec([]) };
  }
}

const asD1 = (d1: GroupD1): D1Database => d1 as unknown as D1Database;

describe("target categories", () => {
  it("creates a group and resolves it by name (case-insensitive) or id", async () => {
    const d1 = new GroupD1();
    const g = await createTargetGroup(asD1(d1), "shop", "1");
    expect(g.id).toMatch(/^grp_/);
    expect((await getTargetGroupByNameOrId(asD1(d1), "shop"))!.id).toBe(g.id);
    expect((await getTargetGroupByNameOrId(asD1(d1), "SHOP"))!.id).toBe(g.id);
    expect((await getTargetGroupByNameOrId(asD1(d1), g.id))!.name).toBe("shop");
    expect(await getTargetGroupByNameOrId(asD1(d1), "nope")).toBeNull();
    expect(await listTargetGroups(asD1(d1))).toHaveLength(1);
  });

  it("attaches domains to a category and lists them oldest-first", async () => {
    const d1 = new GroupD1();
    const g = await createTargetGroup(asD1(d1), "shop", "1");
    const a = await createTarget(asD1(d1), "b.example", null, g.id);
    const b = await createTarget(asD1(d1), "a.example", null, g.id);
    const solo = await createTarget(asD1(d1), "solo.example", null, null);

    const members = await listTargetsByGroup(asD1(d1), g.id);
    expect(members.map((t) => t.id)).toEqual([a.id, b.id]);
    expect(members.every((t) => t.group_id === g.id)).toBe(true);
    expect(solo.group_id ?? null).toBeNull();
    expect(solo.group_id).not.toBe(g.id);
  });

  it("moves an existing domain into another category", async () => {
    const d1 = new GroupD1();
    const g1 = await createTargetGroup(asD1(d1), "one", "1");
    const g2 = await createTargetGroup(asD1(d1), "two", "1");
    const t = await createTarget(asD1(d1), "x.example", null, g1.id);

    await setTargetGroup(asD1(d1), t.id, g2.id);
    expect(await listTargetsByGroup(asD1(d1), g1.id)).toHaveLength(0);
    expect((await listTargetsByGroup(asD1(d1), g2.id)).map((x) => x.id)).toEqual([t.id]);

    await setTargetGroup(asD1(d1), t.id, null);
    expect(await listTargetsByGroup(asD1(d1), g2.id)).toHaveLength(0);
  });

  it("deleting a category detaches its domains (never deletes them)", async () => {
    const d1 = new GroupD1();
    const g = await createTargetGroup(asD1(d1), "shop", "1");
    await createTarget(asD1(d1), "keep.example", null, g.id);
    expect(d1.targets).toHaveLength(1);

    await deleteTargetGroup(asD1(d1), g.id);
    expect(await getTargetGroupByNameOrId(asD1(d1), "shop")).toBeNull();
    expect(d1.targets).toHaveLength(1); // domain survives
    expect(d1.targets[0]!.group_id).toBeNull();
  });
});

describe("group overview (target-info data)", () => {
  it("aggregates last scan, exclusions and per-domain feature maps in one pass", async () => {
    const d1 = new GroupD1();
    const g = await createTargetGroup(asD1(d1), "shop", "1");
    const a = await createTarget(asD1(d1), "a.example", null, g.id);
    const b = await createTarget(asD1(d1), "b.example", null, g.id);

    d1.scans.push({ target_id: a.id, created_at: "2024-01-02T00:00:00Z" });
    d1.scans.push({ target_id: a.id, created_at: "2024-01-05T00:00:00Z" });
    d1.scopes.push({ target_id: a.id, is_denylist: 1, status: "active" });
    d1.scopes.push({ target_id: a.id, is_denylist: 1, status: "removed" });

    // Feature toggles differ per domain — the whole point.
    await setFeature(asD1(d1), a.id, "port_watch", false, "1");
    await setFeature(asD1(d1), a.id, "nuclei", true, "1");

    const overview = await loadTargetOverview(asD1(d1), [a.id, b.id]);

    expect(overview.lastScan.get(a.id)).toBe("2024-01-05T00:00:00Z");
    expect(overview.lastScan.get(b.id)).toBeNull();
    expect(overview.exclusions.get(a.id)).toBe(1); // removed exclusion not counted
    expect(overview.exclusions.get(b.id)).toBe(0);

    const mapA = overview.features.get(a.id)!;
    expect(mapA.port_watch).toBe(false); // per-domain override
    expect(mapA.nuclei).toBe(true);      // per-domain override
    const mapB = overview.features.get(b.id)!;
    expect(mapB.port_watch).toBe(true);  // untouched domain keeps the default
    expect(mapB.nuclei).toBe(false);
    expect(countEnabled(mapA)).toBe(FEATURE_COUNT - 1);
    expect(countEnabled(mapB)).toBe(FEATURE_COUNT - 1);
  });
});

describe("feature isolation across domains", () => {
  it("toggling one domain never leaks to its category sibling", async () => {
    const d1 = new GroupD1();
    const g = await createTargetGroup(asD1(d1), "shop", "1");
    const a = await createTarget(asD1(d1), "a.example", null, g.id);
    const b = await createTarget(asD1(d1), "b.example", null, g.id);

    await setFeature(asD1(d1), a.id, "dns_brute", false, "1");

    expect((await getFeatureMap(asD1(d1), a.id)).dns_brute).toBe(false);
    expect((await getFeatureMap(asD1(d1), b.id)).dns_brute).toBe(true);
  });

  it("feature rows survive moving a domain between categories", async () => {
    const d1 = new GroupD1();
    const g1 = await createTargetGroup(asD1(d1), "one", "1");
    const g2 = await createTargetGroup(asD1(d1), "two", "1");
    const t = await createTarget(asD1(d1), "x.example", null, g1.id);
    await setFeature(asD1(d1), t.id, "js_changes", false, "1");

    await setTargetGroup(asD1(d1), t.id, g2.id);
    expect((await getFeatureMap(asD1(d1), t.id)).js_changes).toBe(false);
  });
});

describe("type shapes", () => {
  it("Target carries group_id and TargetGroup has the documented fields", () => {
    const t: Target = {
      id: "tgt_1", organization_id: "default", name: "x.example",
      group_id: "grp_1", passive_only: true, low_impact_active: false,
      intrusive_enabled: false, max_request_rate_per_min: 60,
      max_concurrent_jobs: 1, program_rules_url: null,
      authorization_reference: "public-program",
      authorization_expires_at: "9999-12-31T23:59:59.000Z",
      paused: false, created_at: "2024-01-01T00:00:00Z",
    };
    const g: TargetGroup = {
      id: "grp_1", name: "shop", organization_id: "default",
      created_at: "2024-01-01T00:00:00Z", created_by: "1",
    };
    expect(t.group_id).toBe("grp_1");
    expect(g.name).toBe("shop");
    const standalone: Target = { ...t, id: "tgt_2", group_id: null };
    expect(standalone.group_id).toBeNull();
    // Legacy fixtures may omit group_id entirely (optional on the type).
    const { group_id: _omit, ...base } = t;
    const legacy: Target = { ...base, id: "tgt_3" };
    expect(legacy.group_id).toBeUndefined();
  });
});



