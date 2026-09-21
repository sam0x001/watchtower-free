// src/db/emergency-stop.ts
// D1-backed emergency stop — replaces the EmergencyStopDO Durable Object.
//
// Single row in `emergency_stop_state` (orgId=GLOBAL or orgId=<org-id> or
// targetId=<target-id> or jobId=<job-id>). When a row exists and is active
// and not expired, scanning is blocked.

interface EmergencyStopRow {
  scope: "global" | "organization" | "target" | "job";
  id: string | null;
  active: boolean;
  reason: string | null;
  activated_by: string | null;
  activated_at: string;
  expires_at: string | null;
}

function normalizeScopeKey(scope: "global" | "organization" | "target" | "job", id?: string | null): string {
  if (scope === "global") return "GLOBAL";
  return id ?? "GLOBAL";
}

export async function isEmergencyStopActive(
  db: D1Database,
  scope: "global" | "organization" | "target" | "job",
  id?: string | null,
): Promise<boolean> {
  const key = normalizeScopeKey(scope, id);
  const now = new Date().toISOString();
  const row = await db
    .prepare(`SELECT active, expires_at FROM emergency_stop_state WHERE scope = ? AND id = ? LIMIT 1`)
    .bind(scope, key)
    .first<{ active: number; expires_at: string | null }>();
  if (!row) return false;
  if (!row.active) return false;
  if (row.expires_at && row.expires_at < now) {
    // Auto-expire
    await db
      .prepare(`UPDATE emergency_stop_state SET active = 0 WHERE scope = ? AND id = ?`)
      .bind(scope, key)
      .run();
    return false;
  }
  return true;
}

export async function activateEmergencyStop(
  db: D1Database,
  scope: "global" | "organization" | "target" | "job",
  opts: { id?: string | null; user_id?: string | null; reason?: string | null; ttl_seconds?: number | null },
): Promise<void> {
  const key = normalizeScopeKey(scope, opts.id);
  const now = new Date();
  const expiresAt = opts.ttl_seconds
    ? new Date(now.getTime() + opts.ttl_seconds * 1000).toISOString()
    : null;
  await db
    .prepare(`INSERT INTO emergency_stop_state (scope, id, active, reason, activated_by, activated_at, expires_at)
              VALUES (?, ?, 1, ?, ?, ?, ?)
              ON CONFLICT(scope, id) DO UPDATE SET
                active = 1,
                reason = excluded.reason,
                activated_by = excluded.activated_by,
                activated_at = excluded.activated_at,
                expires_at = excluded.expires_at`)
    .bind(scope, key, opts.reason ?? null, opts.user_id ?? null, now.toISOString(), expiresAt)
    .run();
}

export async function deactivateEmergencyStop(
  db: D1Database,
  scope: "global" | "organization" | "target" | "job",
  id?: string | null,
): Promise<void> {
  const key = normalizeScopeKey(scope, id);
  await db
    .prepare(`UPDATE emergency_stop_state SET active = 0 WHERE scope = ? AND id = ?`)
    .bind(scope, key)
    .run();
}

export async function cancelJobEmergency(db: D1Database, jobId: string, userId: string | null, reason: string): Promise<void> {
  // Two steps: mark job as cancelled in job_queue + activate a per-job estop
  await db
    .prepare(`UPDATE job_queue SET status = 'cancelled', completed_at = ?, last_error = ? WHERE id = ?`)
    .bind(new Date().toISOString(), `cancelled: ${reason}`, jobId)
    .run();
  await activateEmergencyStop(db, "job", { id: jobId, user_id: userId, reason });
}

/**
 * Drop-in compatibility client so callers in scan-consumer / cron handler don't
 * need to change their import paths.
 */
export class EmergencyStopClient {
  constructor(private db: D1Database) {}

  async isBlocked(scope: "global" | "organization" | "target" | "job", id?: string): Promise<boolean> {
    return isEmergencyStopActive(this.db, scope, id);
  }

  async activate(
    scope: "global" | "organization" | "target" | "job",
    opts: { id?: string; user_id?: string | null; reason?: string | null; ttl_seconds?: number | null },
  ): Promise<void> {
    await activateEmergencyStop(this.db, scope, opts);
  }

  async deactivate(scope: "global" | "organization" | "target" | "job", id?: string): Promise<void> {
    await deactivateEmergencyStop(this.db, scope, id);
  }

  async cancelJob(jobId: string, userId: string | null, reason: string): Promise<void> {
    await cancelJobEmergency(this.db, jobId, userId, reason);
  }

  async state(): Promise<{ global: boolean; perOrganization: Record<string, boolean>; perTarget: Record<string, boolean>; perJob: Record<string, boolean> }> {
    const rows = await db_all(this.db, `SELECT scope, id, active, expires_at FROM emergency_stop_state WHERE active = 1`);
    const now = Date.now();
    let global = false;
    const perOrganization: Record<string, boolean> = {};
    const perTarget: Record<string, boolean> = {};
    const perJob: Record<string, boolean> = {};
    for (const r of rows) {
      const isActive = r.active === 1 && (!r.expires_at || new Date(r.expires_at).getTime() > now);
      if (!isActive) continue;
      if (r.scope === "global") global = true;
      else if (r.scope === "organization" && r.id) perOrganization[r.id] = true;
      else if (r.scope === "target" && r.id) perTarget[r.id] = true;
      else if (r.scope === "job" && r.id) perJob[r.id] = true;
    }
    return { global, perOrganization, perTarget, perJob };
  }
}

async function db_all(db: D1Database, sql: string): Promise<Array<{ scope: string; id: string | null; active: number; expires_at: string | null }>> {
  const result = await db.prepare(sql).all<{ scope: string; id: string | null; active: number; expires_at: string | null }>();
  return result.results ?? [];
}
