// test/assets-schema.test.ts
// Runs the real asset-family upserts against the REAL migration schema.
//
// Regression: `upsertCertificate` omitted `created_at` / `updated_at`, which
// are `TEXT NOT NULL` with no default in migrations/0002. The INSERT therefore
// failed with SQLITE_CONSTRAINT_NOTNULL, and because the CT phase upserts one
// certificate per asset in a single `runScanForTarget` call, the throw aborted
// the entire scan — the operator saw "Scan of <domain> failed" and got no
// results at all, on every target with CT data.
//
// A hand-written D1 double cannot catch this class of bug: the double accepts
// whatever columns the code passes. Only the actual CREATE TABLE statements can.
// This test therefore builds a real in-memory SQLite database from
// migrations/*.sql and executes the production upserts through a thin D1
// adapter, so a column/placeholder drift fails the build instead of production.

import { describe, it, expect, beforeAll } from "vitest";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { createRequire } from "node:module";
import {
  upsertCertificate,
  upsertDnsRecord,
  upsertJavascriptFile,
  insertApiEndpoint,
  upsertAsset,
  upsertService,
  upsertTechnology,
} from "../src/db/queries/assets.js";
import { insertFinding } from "../src/db/queries/findings.js";
import { setFeature } from "../src/db/queries/features.js";

const MIGRATIONS_DIR = fileURLToPath(new URL("../migrations", import.meta.url));

// Resolved synchronously on purpose: Vitest hoists `describe` calls above
// top-level await, so a dynamic import would leave `sqlite` unset when
// `skipIf` is evaluated and the whole suite would skip silently.
//
// @types/node is pinned to the .nvmrc Node 20, which has no node:sqlite types,
// so the slice of the API this test uses is declared locally rather than via
// `typeof import("node:sqlite")`.
interface SqliteStatement {
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
  run(...params: unknown[]): { changes: number | bigint };
}
interface SqliteDatabase {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
}
interface SqliteModule {
  DatabaseSync: new (path: string) => SqliteDatabase;
}

const require_ = createRequire(import.meta.url);
const sqlite: SqliteModule | null = (() => {
  try {
    return require_("node:sqlite") as SqliteModule;
  } catch {
    return null; // Node 20 (the .nvmrc pin) has no node:sqlite.
  }
})();

interface ColumnInfo { name: string; notnull: number }

/** Thinnest D1-shaped adapter over node:sqlite, enough for the upserts. */
function makeD1(db: SqliteDatabase): D1Database {
  return {
    prepare(sql: string) {
      const stmt = db.prepare(sql);
      const bind = (...args: unknown[]) => ({
        first: async <T>() => (stmt.get(...args) as T) ?? null,
        all: async <T>() => ({ results: stmt.all(...args) as T[] }),
        run: async () => ({ meta: { changes: Number(stmt.run(...args).changes) } }),
      });
      return { bind, ...bind() };
    },
  } as unknown as D1Database;
}

async function buildSchema(): Promise<SqliteDatabase> {
  const { DatabaseSync } = sqlite!;
  const db = new DatabaseSync(":memory:");
  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    db.exec(await readFile(join(MIGRATIONS_DIR, f), "utf8"));
  }
  return db;
}

/** A target row the upserts' foreign keys point at. */
function seedTarget(db: SqliteDatabase): string {
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO targets (id, name, organization_id, status, created_by, created_at, updated_at)
     VALUES ('tgt_1', 'example.com', 'default', 'active', NULL, ?, ?)`,
  ).run(now, now);
  return "tgt_1";
}

async function seedAsset(db: SqliteDatabase): Promise<string> {
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO assets (id, organization_id, target_id, asset_type, identifier, display_name,
                         in_scope, scope_state, source, first_seen, last_seen, created_at, updated_at)
     VALUES ('asset_1', 'default', 'tgt_1', 'subdomain', 'example.com', 'example.com',
             1, 'allowed', 'scan', ?, ?, ?, ?)`,
  ).run(now, now, now, now);
  return "asset_1";
}

describe.skipIf(!sqlite)("asset upserts conform to the migration schema", () => {
  let db: SqliteDatabase;
  let d1: D1Database;

  beforeAll(async () => {
    db = await buildSchema();
    seedTarget(db);
    await seedAsset(db);
    d1 = makeD1(db);
  });

  it("inserts a certificate (the SQLITE_CONSTRAINT_NOTNULL regression)", async () => {
    const res = await upsertCertificate(
      d1, "asset_1", "Let's Encrypt", "serial-abc", "2026-01-01T00:00:00Z",
      "2026-04-01T00:00:00Z", ["example.com"],
    );
    expect(res.created).toBe(true);

    const row = db.prepare(`SELECT issuer_cn, serial_number, created_at FROM certificates WHERE id = ?`)
      .get(res.id) as { issuer_cn: string; serial_number: string; created_at: string };
    expect(row.issuer_cn).toBe("Let's Encrypt");
    expect(row.serial_number).toBe("serial-abc");
    // The column that used to be missing.
    expect(row.created_at).toBeTruthy();
  });

  it("treats a re-seen certificate as existing, not new", async () => {
    const again = await upsertCertificate(
      d1, "asset_1", "Let's Encrypt", "serial-abc", "2026-01-01T00:00:00Z",
      "2026-05-01T00:00:00Z", ["example.com"],
    );
    expect(again.created).toBe(false);
  });

  it("inserts a DNS record and updates it in place", async () => {
    const first = await upsertDnsRecord(d1, "asset_1", "A", "example.com", "93.184.216.34", 300);
    expect(first.created).toBe(true);
    const second = await upsertDnsRecord(d1, "asset_1", "A", "example.com", "93.184.216.34", 300);
    expect(second.created).toBe(false);
    expect(second.id).toBe(first.id);
  });

  it("inserts a JavaScript file and reports the previous hash on change", async () => {
    const first = await upsertJavascriptFile(
      d1, "asset_1", "https://example.com/app.js", "hash-1", 1024, null, null, "application/javascript",
    );
    expect(first.created).toBe(true);
    const changed = await upsertJavascriptFile(
      d1, "asset_1", "https://example.com/app.js", "hash-2", 2048, null, null, "application/javascript",
    );
    expect(changed.created).toBe(false);
    expect(changed.previous_sha).toBe("hash-1");
  });

  it("inserts an API endpoint and dedupes on (asset, method, path)", async () => {
    const first = await insertApiEndpoint(d1, "asset_1", "GET", "/api/v1/users", [], "js-extraction");
    expect(first.inserted).toBe(true);
    const second = await insertApiEndpoint(d1, "asset_1", "GET", "/api/v1/users", [], "js-extraction");
    expect(second.inserted).toBe(false);
  });

  it("inserts an asset and reports re-inserts as existing", async () => {
    const first = await upsertAsset(d1, "tgt_1", "subdomain", "new.example.com", "new.example.com", "in_scope");
    expect(first.created).toBe(true);
    const second = await upsertAsset(d1, "tgt_1", "subdomain", "new.example.com", "new.example.com", "in_scope");
    expect(second.created).toBe(false);
  });

  it("inserts a service row (probe phase) without tripping a column constraint", async () => {
    const res = await upsertService(
      d1, "asset_1", 443, "tcp", null, null, 200, "Example Domain", "nginx",
    );
    expect(res.created).toBe(true);
    expect(res.changes).toEqual([]);
  });

  it("inserts a technology row and detects a version change", async () => {
    const first = await upsertTechnology(d1, "asset_1", "nginx", "1.25.0", 0.7, "httpx-worker");
    expect(first.created).toBe(true);
    const bumped = await upsertTechnology(d1, "asset_1", "nginx", "1.26.0", 0.7, "httpx-worker");
    expect(bumped.created).toBe(false);
    expect(bumped.versionChanged).toBe(true);
    expect(bumped.previousVersion).toBe("1.25.0");
  });

  it("inserts a finding and dedupes on fingerprint", async () => {
    const f = {
      targetId: "tgt_1", assetId: "asset_1", findingType: "cve",
      title: "CVE-2026-1", summary: "A known CVE", severity: "high" as const,
      detectionSource: "osv.dev", detectionMethod: "version-match",
      fingerprint: "fp-1",
    };
    expect(await insertFinding(d1, f)).not.toBeNull();
    expect(await insertFinding(d1, f)).toBeNull();
  });

  it("toggles a target feature row", async () => {
    await setFeature(d1, "tgt_1", "port_watch", false, "1");
    const row = db.prepare(`SELECT enabled FROM target_features WHERE target_id = 'tgt_1' AND feature_key = 'port_watch'`).get() as { enabled: number };
    expect(row.enabled).toBe(0);
  });

  it("inserts a target with a root allowlist scope entry", async () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO targets (id, name, organization_id, status, created_by, created_at, updated_at)
       VALUES ('tgt_2', 'other.example', 'default', 'active', NULL, ?, ?)`,
    ).run(now, now);
    db.prepare(
      `INSERT INTO scopes (id, target_id, scope_type, value, display_value, is_denylist, status, created_by, created_at, updated_at)
       VALUES ('scope_1', 'tgt_2', 'domain', 'other.example', 'other.example', 0, 'active', NULL, ?, ?)`,
    ).run(now, now);
    expect(db.prepare(`SELECT COUNT(*) AS n FROM scopes WHERE target_id = 'tgt_2'`).get()).toEqual({ n: 1 });
  });

  // The follow-up pass queued by /scan uses trigger='continuation'; a value the
  // scans CHECK constraint does not list would abort the INSERT and silently
  // drop the background pass the operator was promised.
  it("accepts the 'continuation' trigger used by the post-/scan follow-up", async () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO scans (id, organization_id, target_id, trigger, status, requested_by, created_at, updated_at)
       VALUES ('scan_1', 'default', 'tgt_1', 'continuation', 'queued', '42', ?, ?)`,
    ).run(now, now);
    const row = db.prepare(`SELECT trigger, status FROM scans WHERE id = 'scan_1'`).get() as
      { trigger: string; status: string };
    expect(row.trigger).toBe("continuation");
    expect(row.status).toBe("queued");
  });
});

// ---------------------------------------------------------------------------
// Every asset-family table declares created_at NOT NULL, and all but
// dns_records also declare updated_at NOT NULL. An INSERT that omits a NOT NULL
// column with no default is a runtime error against the real schema.
// ---------------------------------------------------------------------------

const ASSET_TABLES = [
  "assets", "dns_records", "certificates", "services", "technologies",
  "javascript_files", "api_endpoints",
] as const;

/** Tables that declare created_at but NOT updated_at (see migrations/0002). */
const NO_UPDATED_AT = new Set(["dns_records"]);

describe.skipIf(!sqlite)("created_at/updated_at are NOT NULL wherever declared", () => {
  it("gives every asset table a NOT NULL created_at, and updated_at except dns_records", async () => {
    const db = await buildSchema();
    for (const table of ASSET_TABLES) {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all() as unknown as ColumnInfo[];
      const notNull = new Set(cols.filter((c) => c.notnull === 1).map((c) => c.name));

      expect(notNull.has("created_at"), `${table}.created_at should be NOT NULL`).toBe(true);

      if (NO_UPDATED_AT.has(table)) {
        expect(cols.some((c) => c.name === "updated_at"), `${table} should have no updated_at`).toBe(false);
      } else {
        expect(notNull.has("updated_at"), `${table}.updated_at should be NOT NULL`).toBe(true);
      }
    }
  });
});
