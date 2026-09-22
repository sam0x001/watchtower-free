// test/audit-logger.test.ts
// Regression tests for the audit_logs NOT NULL incident (2026-09-21):
//   D1_ERROR: NOT NULL constraint failed: audit_logs.actor_kind
//
// The logger must always write the canonical audit_logs columns declared in
// migrations/0001_initial.sql, including the NOT NULL ones
// (actor_kind, command, result, created_at).

import { describe, it, expect } from "vitest";
import {
  AUDIT_INSERT_COLUMNS,
  AUDIT_INSERT_SQL,
  D1AuditLogger,
  buildAuditRow,
  resolveActorKind,
  resolveAuditResult,
} from "../src/audit/logger.js";
import type { AuditActorKind, AuditEvent } from "../src/types.js";

const COLUMNS: readonly string[] = AUDIT_INSERT_COLUMNS;
const NOT_NULL_COLUMNS = ["actor_kind", "command", "result", "created_at"];
const TABLE_RESULTS = ["success", "denied", "error", "pending_approval"];

function columnValue(row: (string | null)[], column: string): string | null {
  return row[COLUMNS.indexOf(column)] ?? null;
}

function baseEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: "2026-09-21T14:31:12.000Z",
    user_id: null,
    telegram_id: "12345",
    organization_id: "org_1",
    action: "telegram.command.help",
    target_id: null,
    scope_id: null,
    job_id: null,
    scanner: null,
    args_redacted: JSON.stringify({ args: ["help"] }),
    result: "success",
    error: null,
    ip: null,
    request_id: "req_TEST000000",
    ...overrides,
  };
}

/** Minimal D1 double that records the SQL + bound values. */
class RecordingD1 {
  statements: { sql: string; args: unknown[] }[] = [];

  prepare(sql: string) {
    return {
      bind: (...args: unknown[]) => ({
        run: async () => {
          this.statements.push({ sql, args });
          return { meta: { changes: 1 } };
        },
      }),
    };
  }
}

describe("audit_logs canonical mapping", () => {
  it("builds the INSERT from the column list so SQL and binds cannot drift", () => {
    expect(AUDIT_INSERT_SQL).toContain(`INSERT INTO audit_logs (${AUDIT_INSERT_COLUMNS.join(", ")})`);
    expect(AUDIT_INSERT_SQL.split("?").length - 1).toBe(AUDIT_INSERT_COLUMNS.length);
    expect(AUDIT_INSERT_SQL).toContain("actor_kind");
    expect(AUDIT_INSERT_SQL).not.toContain("request_id,");
  });

  it("binds exactly one value per column", () => {
    const row = buildAuditRow(baseEvent());
    expect(row).toHaveLength(AUDIT_INSERT_COLUMNS.length);
  });

  it("always populates the NOT NULL columns", () => {
    const events: AuditEvent[] = [
      baseEvent(),
      baseEvent({ timestamp: "", action: "api.GET./v1/health", result: "failure", telegram_id: null }),
      baseEvent({ action: "", result: "blocked" }),
      baseEvent({ action: "scan.completed", result: "pending_approval", telegram_id: null }),
      baseEvent({ action: "telegram.command.unauthorized", result: "denied" }),
    ];

    for (const event of events) {
      const row = buildAuditRow(event);
      for (const column of NOT_NULL_COLUMNS) {
        expect(columnValue(row, column), `${column} must not be empty`).toBeTruthy();
      }
      // result must satisfy the audit_logs CHECK constraint
      expect(TABLE_RESULTS).toContain(columnValue(row, "result"));
    }
  });

  it("maps the in-memory result vocabulary onto the table CHECK constraint", () => {
    expect(resolveAuditResult("success")).toBe("success");
    expect(resolveAuditResult("denied")).toBe("denied");
    expect(resolveAuditResult("failure")).toBe("error");
    expect(resolveAuditResult("blocked")).toBe("denied");
    expect(resolveAuditResult("pending_approval")).toBe("pending_approval");
  });

  it("infers actor_kind and honours an explicit value", () => {
    const inferred: [Partial<AuditEvent>, AuditActorKind][] = [
      [{ action: "telegram.command.audit" }, "telegram"],
      [{ action: "api.PATCH./v1/findings" }, "api"],
      [{ action: "runner.callback.received" }, "runner"],
      [{ action: "webhook.delivery.received" }, "webhook"],
      [{ action: "scan.completed", telegram_id: null }, "system"],
    ];
    for (const [overrides, expected] of inferred) {
      expect(resolveActorKind(baseEvent(overrides))).toBe(expected);
    }
    expect(resolveActorKind(baseEvent({ action: "scan.completed", actor_kind: "runner" }))).toBe("runner");
  });

  it("keeps the ip in request_metadata and the request id in correlation_id", () => {
    const row = buildAuditRow(baseEvent({ ip: "203.0.113.7" }));
    expect(columnValue(row, "correlation_id")).toBe("req_TEST000000");
    expect(JSON.parse(columnValue(row, "request_metadata") ?? "{}")).toEqual({
      ip: "203.0.113.7",
      user_id: null,
      telegram_id: "12345",
    });
  });

  it("writes a full row through D1AuditLogger without missing NOT NULL values", async () => {
    const db = new RecordingD1();
    const logger = new D1AuditLogger(db as unknown as D1Database);

    await logger.log(baseEvent({ result: "failure", error: "boom" }));

    expect(db.statements).toHaveLength(1);
    const { sql, args } = db.statements[0]!;
    expect(sql).toContain("INSERT INTO audit_logs");
    expect(args).toHaveLength(AUDIT_INSERT_COLUMNS.length);
    expect(args[COLUMNS.indexOf("actor_kind")]).toBe("telegram");
    expect(args[COLUMNS.indexOf("command")]).toBe("telegram.command.help");
    expect(args[COLUMNS.indexOf("result")]).toBe("error");
    expect(args[COLUMNS.indexOf("created_at")]).toBe("2026-09-21T14:31:12.000Z");
    expect(args[COLUMNS.indexOf("result_detail")]).toBe("boom");
  });

  it("still scrubs suspected secrets from args before they reach D1", async () => {
    const db = new RecordingD1();
    const logger = new D1AuditLogger(db as unknown as D1Database);

    await logger.log(baseEvent({
      args_redacted: JSON.stringify({ authorization: "Bearer abc123", note: "AKIAIOSFODNN7EXAMPLE" }),
    }));

    const stored = String(db.statements[0]!.args[COLUMNS.indexOf("arguments_redacted")]);
    expect(stored).not.toContain("abc123");
    expect(stored).toContain("<redacted>");
  });
});
