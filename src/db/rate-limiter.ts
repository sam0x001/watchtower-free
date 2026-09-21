// src/db/rate-limiter.ts
// D1-backed rate limiter — replaces the RateLimiterDO Durable Object.
//
// Sliding window: stores up to `MAX_HITS_PER_KEY` recent hit timestamps as a
// JSON array in `rate_limits_v2`. When the array grows beyond the window, the
// oldest entries are dropped.
//
// Also tracks consecutive_errors + backoff_until for circuit-breaker behavior.

const MAX_HITS_PER_KEY = 200;  // bounded memory per key
const WINDOW_MS = 60_000;

interface RateLimitRow {
  key: string;
  hits_json: string;        // JSON array of timestamps (ms)
  backoff_until: number;    // ms epoch
  consecutive_errors: number;
  updated_at: string;
}

export class RateLimiterClient {
  constructor(private db: D1Database) {}

  /**
   * Check whether a request is allowed under the rate limit. Does NOT record
   * a hit — call `record()` separately after the request completes.
   */
  async check(key: string, limitPerMin: number): Promise<{ allowed: boolean; retryAfterMs?: number; remaining: number }> {
    const now = Date.now();
    const row = await this.db
      .prepare(`SELECT hits_json, backoff_until, consecutive_errors FROM rate_limits_v2 WHERE key = ?`)
      .bind(key)
      .first<RateLimitRow>();

    if (!row) {
      return { allowed: true, remaining: limitPerMin };
    }

    if (row.backoff_until > now) {
      return { allowed: false, retryAfterMs: row.backoff_until - now, remaining: 0 };
    }

    // Circuit breaker: too many consecutive errors triggers a 30s backoff
    if (row.consecutive_errors >= 5) {
      await this.db
        .prepare(`UPDATE rate_limits_v2 SET backoff_until = ? WHERE key = ?`)
        .bind(now + 30_000, key)
        .run();
      return { allowed: false, retryAfterMs: 30_000, remaining: 0 };
    }

    const hits = JSON.parse(row.hits_json) as number[];
    const recentHits = hits.filter((t) => now - t < WINDOW_MS);
    const allowed = recentHits.length < limitPerMin;
    return {
      allowed,
      remaining: Math.max(0, limitPerMin - recentHits.length),
      retryAfterMs: allowed ? undefined : WINDOW_MS,
    };
  }

  /**
   * Record a hit. Call after the request completes — pass `error=true` if the
   * request failed (429, 5xx, timeout) so the circuit-breaker can engage.
   */
  async record(key: string, error: boolean): Promise<void> {
    const now = Date.now();
    const row = await this.db
      .prepare(`SELECT hits_json, consecutive_errors FROM rate_limits_v2 WHERE key = ?`)
      .bind(key)
      .first<{ hits_json: string; consecutive_errors: number }>();

    if (!row) {
      const hits = [now];
      await this.db
        .prepare(`INSERT INTO rate_limits_v2 (key, hits_json, backoff_until, consecutive_errors, updated_at) VALUES (?, ?, 0, ?, ?)`)
        .bind(key, JSON.stringify(hits), error ? 1 : 0, new Date().toISOString())
        .run();
      return;
    }

    const hits = JSON.parse(row.hits_json) as number[];
    const recentHits = hits.filter((t) => now - t < WINDOW_MS);
    recentHits.push(now);
    if (recentHits.length > MAX_HITS_PER_KEY) recentHits.splice(0, recentHits.length - MAX_HITS_PER_KEY);

    const consecutiveErrors = error ? (row.consecutive_errors ?? 0) + 1 : 0;
    await this.db
      .prepare(`UPDATE rate_limits_v2 SET hits_json = ?, consecutive_errors = ?, updated_at = ? WHERE key = ?`)
      .bind(JSON.stringify(recentHits), consecutiveErrors, new Date().toISOString(), key)
      .run();
  }

  async backoff(key: string, ms: number): Promise<void> {
    await this.db
      .prepare(`UPDATE rate_limits_v2 SET backoff_until = ?, consecutive_errors = consecutive_errors + 1 WHERE key = ?
                OR (INSERT INTO rate_limits_v2 (key, hits_json, backoff_until, consecutive_errors, updated_at) VALUES (?, '[]', ?, 1, ?))`)
      .bind(Date.now() + ms, key, key, Date.now() + ms, new Date().toISOString())
      .run();
  }

  async reset(key: string): Promise<void> {
    await this.db
      .prepare(`DELETE FROM rate_limits_v2 WHERE key = ?`)
      .bind(key)
      .run();
  }
}
