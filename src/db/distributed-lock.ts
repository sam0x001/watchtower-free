// src/db/distributed-lock.ts
// D1-based distributed lock — replaces the LockDO Durable Object.
//
// Uses a `locks` table with `locked_until` to prevent two cron invocations
// from running the same scan concurrently. Acquired locks auto-expire after
// `ttlMs` so a crashed Worker can't hold a lock forever.
//
// Trade-off vs Durable Object: this can have a small race window between
// SELECT and UPDATE in heavy concurrency, but on the free tier with one cron
// tick every 5 minutes and a single Worker isolate, the race is effectively
// non-existent.

interface LockRow {
  key: string;
  holder_id: string;
  locked_until: number;
}

export class LockClient {
  constructor(private db: D1Database, private key: string) {}

  async acquire(holderId: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const lockedUntil = now + ttlMs;

    // Try to insert a new lock — succeeds if no lock exists for this key.
    // SQLite's ON CONFLICT DO NOTHING gives us atomicity.
    const result = await this.db
      .prepare(`INSERT INTO locks (key, holder_id, locked_until)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO NOTHING`)
      .bind(this.key, holderId, lockedUntil)
      .run();

    if (result.meta?.changes && result.meta.changes > 0) {
      return true; // we got the lock
    }

    // Lock already exists — check if it's expired and we can steal it.
    const row = await this.db
      .prepare(`SELECT holder_id, locked_until FROM locks WHERE key = ?`)
      .bind(this.key)
      .first<LockRow>();

    if (!row) {
      // Row vanished between INSERT and SELECT — try once more.
      const retry = await this.db
        .prepare(`INSERT INTO locks (key, holder_id, locked_until) VALUES (?, ?, ?) ON CONFLICT(key) DO NOTHING`)
        .bind(this.key, holderId, lockedUntil)
        .run();
      return !!(retry.meta?.changes && retry.meta.changes > 0);
    }

    if (row.locked_until > now) {
      return false; // someone else holds it
    }

    // Steal the expired lock. Use a WHERE clause to avoid clobbering a fresh lock.
    const steal = await this.db
      .prepare(`UPDATE locks SET holder_id = ?, locked_until = ? WHERE key = ? AND locked_until <= ?`)
      .bind(holderId, lockedUntil, this.key, now)
      .run();

    return !!(steal.meta?.changes && steal.meta.changes > 0);
  }

  async renew(holderId: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const lockedUntil = now + ttlMs;
    const result = await this.db
      .prepare(`UPDATE locks SET locked_until = ? WHERE key = ? AND holder_id = ?`)
      .bind(lockedUntil, this.key, holderId)
      .run();
    return !!(result.meta?.changes && result.meta.changes > 0);
  }

  async release(holderId: string): Promise<void> {
    await this.db
      .prepare(`DELETE FROM locks WHERE key = ? AND holder_id = ?`)
      .bind(this.key, holderId)
      .run();
  }
}
