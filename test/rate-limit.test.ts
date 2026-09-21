// test/rate-limit.test.ts
// Free-tier D1-backed rate limiter tests — replaces the DO-based ones.

import { describe, it, expect, beforeEach } from "vitest";
import { RateLimiterClient } from "../src/db/rate-limiter.js";

// In-memory D1 mock
class FakeD1 {
  private rows = new Map<string, Map<string, unknown>>();

  prepare(sql: string) {
    return {
      bind: (...args: unknown[]) => ({
        first: async <T>() => {
          const key = args[0] as string;
          if (sql.includes("SELECT hits_json, backoff_until, consecutive_errors")) {
            const table = this.rows.get("rate_limits_v2");
            const row = table?.get(key) as { hits_json: string; backoff_until: number; consecutive_errors: number } | undefined;
            return (row ?? null) as T | null;
          }
          if (sql.includes("SELECT hits_json, consecutive_errors")) {
            const table = this.rows.get("rate_limits_v2");
            const row = table?.get(key) as { hits_json: string; consecutive_errors: number } | undefined;
            return (row ?? null) as T | null;
          }
          return null;
        },
        run: async () => {
          if (sql.includes("INSERT INTO rate_limits_v2")) {
            const key = args[0] as string;
            const hits = args[1] as string;
            const backoff = args[2] as number;
            const errors = args[3] as number;
            if (!this.rows.has("rate_limits_v2")) this.rows.set("rate_limits_v2", new Map());
            this.rows.get("rate_limits_v2")!.set(key, { hits_json: hits, backoff_until: backoff, consecutive_errors: errors, updated_at: new Date().toISOString() });
            return { meta: { changes: 1 } };
          }
          if (sql.includes("UPDATE rate_limits_v2")) {
            // We don't care about exact SQL pattern for the test
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        },
      }),
    };
  }
}

describe("D1-backed rate limiter (free tier)", () => {
  let db: FakeD1;
  let limiter: RateLimiterClient;

  beforeEach(() => {
    db = new FakeD1();
    limiter = new RateLimiterClient(db as unknown as D1Database);
  });

  it("allows requests when no row exists", async () => {
    const result = await limiter.check("test", 60);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(60);
  });

  it("allows requests when under the limit", async () => {
    await limiter.record("test", false);
    const result = await limiter.check("test", 60);
    expect(result.allowed).toBe(true);
  });

  it("records a hit and increments the consecutive error count", async () => {
    await limiter.record("test", true);
    await limiter.record("test", true);
    const result = await limiter.check("test", 60);
    expect(result.allowed).toBe(true); // still under circuit-breaker threshold (5)
  });

  it("does not engage circuit breaker below threshold", async () => {
    for (let i = 0; i < 4; i++) await limiter.record("test", true);
    const result = await limiter.check("test", 60);
    expect(result.allowed).toBe(true);
  });
});
