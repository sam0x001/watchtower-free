// src/db/client.ts
// Thin D1 wrapper used by all query modules.

import type { Env } from "../env.js";

export interface Pagination {
  limit: number;
  offset: number;
}

export interface Sort {
  field: string;
  direction: "asc" | "desc";
}

export function sanitizeSort(field: string, allowed: string[], fallback: string): Sort {
  if (!allowed.includes(field)) return { field: fallback, direction: "desc" };
  return { field, direction: "desc" };
}

export function clampPagination(limit?: number, offset?: number): Pagination {
  return {
    limit: Math.min(Math.max(1, limit ?? 50), 200),
    offset: Math.max(0, offset ?? 0),
  };
}

export class Db {
  constructor(private raw: D1Database) {}

  prepare(sql: string): D1PreparedStatement {
    return this.raw.prepare(sql);
  }

  async exec(sql: string): Promise<void> {
    await this.raw.exec(sql);
  }

  async transaction<T>(fn: (db: D1Database) => Promise<T>): Promise<T> {
    return this.raw.batch([
      this.raw.prepare("BEGIN"),
    ]).then(async () => {
      try {
        const result = await fn(this.raw);
        await this.raw.exec("COMMIT");
        return result;
      } catch (err) {
        await this.raw.exec("ROLLBACK");
        throw err;
      }
    });
  }
}

export function db(env: Env): D1Database {
  return env.DB;
}
