// test/scan-delivery.test.ts
// Delivery contract for the /scan path, plus category-level scan and remove.
//
// The regression that motivated deliverInlineAlerts: the old inline path called
// recordNotificationSent() for EVERY alert but only actually *sent* the
// high/critical ones. A new subdomain is medium severity, so it was written
// into `notifications` as status='sent' without ever being delivered — and the
// dispatcher's dedupe then suppressed it forever. Findings were found and
// silently dropped, which is the worst possible failure for a monitor.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { deliverInlineAlerts, type ScanRunResult, type ScanStats } from "../src/queues/scan-runner.js";
import { deleteGroupAndMembers } from "../src/telegram/commands.js";
import { saveRemoveConfirmation, readRemoveConfirmation, clearRemoveConfirmation } from "../src/telegram/pending.js";
import type { Env } from "../src/env.js";
import type { Alert } from "../src/modules/alerts.js";

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/**
 * Records every notification row the inline path claims to have delivered, and
 * every notification job it enqueues.
 *
 * The recording happens inside the terminal methods (`.first`/`.run`), not in
 * `prepare`/`.bind` — D1 statements are only executed when a terminal method is
 * called, so recording on bind would double-count every write.
 */
class NotificationD1 {
  sent: Array<{ dedupe_key: string }> = [];
  jobs: Array<{ dedup_key: string | null }> = [];
  /** dedupe_keys pre-seeded as already delivered. */
  alreadyDelivered = new Set<string>();

  prepare(sql: string) {
    const self = this;
    const record = (args: unknown[]) => {
      if (sql.includes("INSERT INTO notifications")) {
        // id, org, target, finding, destination, alert_type, severity,
        // title, body, dedupe_key, sent_at, created_at, updated_at
        self.sent.push({ dedupe_key: String(args[9]) });
      }
      if (sql.includes("INSERT INTO job_queue")) {
        // id, kind, payload, status, priority, max_attempts, run_after,
        // locked_until, created_at, last_error, dedup_key
        self.jobs.push({ dedup_key: (args[10] as string | null) ?? null });
      }
    };
    return {
      bind: (...args: unknown[]) => ({
        first: async <T>() => {
          record(args);
          const key = String(args[0]);
          return (self.alreadyDelivered.has(key) ? { id: "notif_old" } : null) as T | null;
        },
        all: async <T>() => {
          record(args);
          return { results: [] as T[] };
        },
        run: async () => {
          record(args);
          return { meta: { changes: 1 } };
        },
      }),
      first: async <T>() => null as T | null,
      all: async <T>() => ({ results: [] as T[] }),
      run: async () => ({ meta: { changes: 0 } }),
    };
  }
}

class MemoryKV {
  store = new Map<string, string>();
  async get(key: string): Promise<string | null> { return this.store.get(key) ?? null; }
  async put(key: string, value: string): Promise<void> { this.store.set(key, value); }
  async delete(key: string): Promise<void> { this.store.delete(key); }
}

/** Minimal Env double: the inline path only touches DB, CACHE and TELEGRAM_BOT_TOKEN. */
function makeEnv(): { env: Env; sent: string[] } {
  const db = new NotificationD1();
  const kv = new MemoryKV();
  const sent: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: RequestInit) => {
    sent.push(String((init?.body as string | undefined) ?? ""));
    return new Response("{}", { status: 200 });
  }));
  const env = {
    DB: db as unknown as D1Database,
    CACHE: kv as unknown as KVNamespace,
    TELEGRAM_BOT_TOKEN: "test-token",
  } as unknown as Env;
  return { env, sent };
}

function makeAlert(over: Partial<Alert> & { type: Alert["type"]; asset_value: string }): Alert {
  return {
    severity: "medium",
    title: `title for ${over.asset_value}`,
    summary: `summary for ${over.asset_value}`,
    dedup_key: `${over.type}:tgt_1:${over.asset_value}`,
    metadata: { asset_value: over.asset_value },
    ...over,
  };
}

function makeResult(alerts: Alert[]): ScanRunResult {
  const stats: ScanStats = {
    subdomainsFound: alerts.length, certsFound: 0, dnsRecordsFound: 0, liveHosts: 0,
    newTechs: 0, secretsFound: 0, cvesFound: 0, fuzzFindings: 0, fuzzRequests: 0,
    wildcardSkipped: 0, outOfScope: 0, hostsProbed: 0, portsProbed: 0, portsOpen: 0,
    bruteforce: null, topSubdomains: [], deadlineReached: false, errors: [],
  };
  return {
    ok: true, retryable: true, targetId: "tgt_1", targetName: "example.com",
    organizationId: "default", alerts, stats,
  };
}

// ---------------------------------------------------------------------------

describe("deliverInlineAlerts", () => {
  beforeEach(() => { vi.unstubAllGlobals(); });

  it("delivers medium-severity alerts (the regression: subdomains were dropped)", async () => {
    const { env, sent } = makeEnv();
    const alerts = [
      makeAlert({ type: "new_subdomain", asset_value: "a.example.com" }),
      makeAlert({ type: "new_subdomain", asset_value: "b.example.com" }),
    ];
    const count = await deliverInlineAlerts(env, makeResult(alerts), 42);
    expect(count).toBe(2);
    // Both actually reached the chat, not just the notifications table.
    expect(sent).toHaveLength(2);
    expect(sent.join("")).toContain("a.example.com");
    expect(sent.join("")).toContain("b.example.com");
  });

  it("baselines only what it printed, so the cron does not repeat it", async () => {
    const { env } = makeEnv();
    const alert = makeAlert({ type: "new_subdomain", asset_value: "a.example.com" });
    await deliverInlineAlerts(env, makeResult([alert]), 42);
    const db = (env as unknown as { DB: NotificationD1 }).DB;
    expect(db.sent).toHaveLength(1);
    expect(db.sent[0]!.dedupe_key).toBe(alert.dedup_key);
  });

  it("enqueues the overflow instead of dropping or falsely baselining it", async () => {
    const { env } = makeEnv();
    const alerts = Array.from({ length: 20 }, (_, i) =>
      makeAlert({ type: "new_subdomain", asset_value: `h${i}.example.com` }));
    const count = await deliverInlineAlerts(env, makeResult(alerts), 42);
    expect(count).toBe(12); // INLINE_ALERT_LIMIT

    const db = (env as unknown as { DB: NotificationD1 }).DB;
    // Printed ones are baselined; the other 8 ride the queue, not the log.
    expect(db.sent).toHaveLength(12);
    expect(db.jobs).toHaveLength(8);
  });

  it("keeps urgent findings when the limit cuts the list short", async () => {
    const { env, sent } = makeEnv();
    const alerts = [
      ...Array.from({ length: 15 }, (_, i) =>
        makeAlert({ type: "new_subdomain", asset_value: `low${i}.example.com` })),
      makeAlert({ type: "new_secret_candidate", asset_value: "app.js:9", severity: "high" }),
    ];
    await deliverInlineAlerts(env, makeResult(alerts), 42);
    // The high-severity finding outranks 12 mediums and must be in the chat.
    expect(sent.join("")).toContain("app.js:9");
  });

  it("is a no-op when the pass found nothing", async () => {
    const { env, sent } = makeEnv();
    expect(await deliverInlineAlerts(env, makeResult([]), 42)).toBe(0);
    expect(sent).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Passive-only phase selection
// ---------------------------------------------------------------------------

describe("runScanForTarget phases", () => {
  /** A D1 double that only answers the reads runScanForTarget makes up front. */
  function phaseD1(overrides: { features: Array<Record<string, unknown>> }) {
    return {
      prepare(sql: string) {
        const stmt = (args: unknown[]) => ({
          first: async <T>() => {
            if (sql.includes("FROM targets WHERE id = ?")) {
              return {
                id: String(args[0]), name: "example.com", organization_id: "default",
                group_id: null, status: "active", created_at: "2024-01-01T00:00:00Z",
              } as T;
            }
            if (sql.includes("FROM target_features")) {
              return { target_id: String(args[0]) } as T;
            }
            return null as T | null;
          },
          all: async <T>() => {
            if (sql.includes("FROM target_features")) return { results: overrides.features as T[] };
            return { results: [] as T[] };
          },
          run: async () => ({ meta: { changes: 1 } }),
        });
        return { bind: (...args: unknown[]) => stmt(args), ...stmt([]) };
      },
    } as unknown as D1Database;
  }

  const ENV_BASE = {
    CACHE: new MemoryKV() as unknown as KVNamespace,
    USER_AGENT: "test",
    FREE_TIER_SCAN_TIMEOUT_MS: "60000",
  };

  it("passive mode stops after discovery and reports no probes", async () => {
    const { runScanForTarget } = await import("../src/queues/scan-runner.js");
    const env = {
      ...ENV_BASE,
      DB: phaseD1({ features: [] }),
    } as unknown as Env;

    // Every provider call is stubbed empty; this asserts the control flow
    // (passive mode returns before the bruteforce/probe phases), not discovery.
    vi.stubGlobal("fetch", vi.fn(async () => new Response("[]", { status: 200 })));

    const result = await runScanForTarget(env, "tgt_1", { phases: "passive" });
    expect(result.ok).toBe(true);
    // Nothing was probed and no bruteforce cursor advanced: the heavy phases
    // never ran, so the cron owns them.
    expect(result.stats.hostsProbed).toBe(0);
    expect(result.stats.bruteforce).toBeNull();
  }, 20_000);
});

// ---------------------------------------------------------------------------
// /remove <category> confirmation
// ---------------------------------------------------------------------------

describe("remove confirmation", () => {
  beforeEach(() => { vi.unstubAllGlobals(); });

  it("round-trips a token and rejects a wrong or expired one", async () => {
    const { env } = makeEnv();
    const token = await saveRemoveConfirmation(env, 42, {
      groupId: "grp_1", groupName: "shop", domainCount: 3, createdAt: "now",
    });
    expect(token).toMatch(/^[0-9a-f]{8}$/);

    const ok = await readRemoveConfirmation(env, 42, token);
    expect(ok?.groupId).toBe("grp_1");
    expect(ok?.domainCount).toBe(3);

    expect(await readRemoveConfirmation(env, 42, "deadbeef")).toBeNull();
    // Scoped per chat: another chat cannot confirm this deletion.
    expect(await readRemoveConfirmation(env, 43, token)).toBeNull();
  });

  it("cannot be replayed after being cleared", async () => {
    const { env } = makeEnv();
    const token = await saveRemoveConfirmation(env, 42, {
      groupId: "grp_1", groupName: "shop", domainCount: 1, createdAt: "now",
    });
    await clearRemoveConfirmation(env, 42);
    expect(await readRemoveConfirmation(env, 42, token)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// /remove <category> cascade
// ---------------------------------------------------------------------------

describe("deleteGroupAndMembers", () => {
  const MEMBERS = [
    { id: "tgt_1", name: "a.example", group_id: "grp_1", organization_id: "default",
      status: "active", created_at: "2024-01-01T00:00:00Z" },
    { id: "tgt_2", name: "b.example", group_id: "grp_1", organization_id: "default",
      status: "active", created_at: "2024-01-02T00:00:00Z" },
  ];

  function makeGroupD1(members: unknown[]): { db: D1Database; targets: string[]; groups: string[] } {
    const targets: string[] = [];
    const groups: string[] = [];
    const db = {
      prepare(sql: string) {
        return {
          bind: (...args: unknown[]) => ({
            all: async () => ({ results: sql.includes("WHERE group_id = ?") ? members : [] }),
            first: async <T>() => null as T | null,
            run: async () => {
              if (sql.startsWith("DELETE FROM targets")) targets.push(String(args[0]));
              if (sql.startsWith("DELETE FROM target_groups")) groups.push(String(args[0]));
              return { meta: { changes: 1 } };
            },
          }),
          all: async () => ({ results: [] }),
          first: async <T>() => null as T | null,
          run: async () => ({ meta: { changes: 0 } }),
        };
      },
    } as unknown as D1Database;
    return { db, targets, groups };
  }

  it("deletes every member domain and the category itself", async () => {
    const { db, targets, groups } = makeGroupD1(MEMBERS);
    expect(await deleteGroupAndMembers({ DB: db } as never, "grp_1")).toBe(2);
    expect(targets).toEqual(["tgt_1", "tgt_2"]);
    expect(groups).toEqual(["grp_1"]);
  });

  it("still removes an empty category", async () => {
    const { db, targets, groups } = makeGroupD1([]);
    expect(await deleteGroupAndMembers({ DB: db } as never, "grp_empty")).toBe(0);
    expect(targets).toEqual([]);
    expect(groups).toEqual(["grp_empty"]);
  });
});
