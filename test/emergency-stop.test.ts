// test/emergency-stop.test.ts
// Free-tier D1-backed emergency stop tests — replaces the DO-based ones.

import { describe, it, expect, beforeEach } from "vitest";
import {
  isEmergencyStopActive,
  activateEmergencyStop,
  deactivateEmergencyStop,
  EmergencyStopClient,
} from "../src/db/emergency-stop.js";

class FakeD1 {
  private rows = new Map<string, Map<string, unknown>>();

  prepare(sql: string) {
    return {
      bind: (...args: unknown[]) => ({
        first: async <T>() => {
          if (sql.includes("SELECT active, expires_at FROM emergency_stop_state")) {
            const scope = args[0] as string;
            const id = args[1] as string;
            const table = this.rows.get("emergency_stop_state");
            const row = table?.get(`${scope}:${id}`) as { active: number; expires_at: string | null } | undefined;
            return (row ?? null) as T | null;
          }
          return null;
        },
        run: async () => {
          if (sql.includes("INSERT INTO emergency_stop_state")) {
            const scope = args[0] as string;
            const id = args[1] as string;
            if (!this.rows.has("emergency_stop_state")) this.rows.set("emergency_stop_state", new Map());
            this.rows.get("emergency_stop_state")!.set(`${scope}:${id}`, {
              active: 1,
              reason: args[2],
              activated_by: args[3],
              activated_at: args[4],
              expires_at: args[5],
            });
            return { meta: { changes: 1 } };
          }
          if (sql.includes("UPDATE emergency_stop_state SET active = 0")) {
            const scope = args[1] as string;
            const id = args[2] as string;
            const row = this.rows.get("emergency_stop_state")?.get(`${scope}:${id}`) as Record<string, unknown> | undefined;
            if (row) {
              row["active"] = 0;
              this.rows.get("emergency_stop_state")!.set(`${scope}:${id}`, row);
            }
            return { meta: { changes: row ? 1 : 0 } };
          }
          return { meta: { changes: 0 } };
        },
        all: async () => ({ results: [] }),
      }),
    };
  }
}

describe("D1-backed emergency stop (free tier)", () => {
  let db: FakeD1;
  let client: EmergencyStopClient;

  beforeEach(() => {
    db = new FakeD1();
    client = new EmergencyStopClient(db as unknown as D1Database);
  });

  it("is initially not blocked globally", async () => {
    expect(await isEmergencyStopActive(db as unknown as D1Database, "global")).toBe(false);
  });

  it("blocks globally after activation", async () => {
    await activateEmergencyStop(db as unknown as D1Database, "global", { user_id: "u1", reason: "test" });
    expect(await isEmergencyStopActive(db as unknown as D1Database, "global")).toBe(true);
  });

  it("deactivates globally", async () => {
    await activateEmergencyStop(db as unknown as D1Database, "global", { user_id: "u1" });
    await deactivateEmergencyStop(db as unknown as D1Database, "global");
    expect(await isEmergencyStopActive(db as unknown as D1Database, "global")).toBe(false);
  });

  it("blocks per-target independently", async () => {
    await activateEmergencyStop(db as unknown as D1Database, "target", { id: "TGT_a", user_id: "u1" });
    expect(await isEmergencyStopActive(db as unknown as D1Database, "target", "TGT_a")).toBe(true);
    expect(await isEmergencyStopActive(db as unknown as D1Database, "target", "TGT_b")).toBe(false);
  });

  it("expires after TTL", async () => {
    await activateEmergencyStop(db as unknown as D1Database, "global", { user_id: "u1", ttl_seconds: 1 });
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(await isEmergencyStopActive(db as unknown as D1Database, "global")).toBe(false);
  });

  it("client.isBlocked returns same result as bare function", async () => {
    await client.activate("global", { user_id: "u1" });
    expect(await client.isBlocked("global")).toBe(true);
    await client.deactivate("global");
    expect(await client.isBlocked("global")).toBe(false);
  });
});
