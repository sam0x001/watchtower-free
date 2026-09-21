// src/db/job-coordinator.ts
// D1-backed job coordinator — replaces the JobCoordinatorDO Durable Object.
//
// Counts active jobs per target by querying the job_queue table. Used to
// enforce MAX_JOBS_PER_TARGET so a single target doesn't monopolize the
// Worker's free-tier CPU budget.

export class JobCoordinatorClient {
  constructor(private db: D1Database) {}

  async count(targetId: string): Promise<number> {
    const row = await this.db
      .prepare(`SELECT COUNT(*) as n FROM job_queue WHERE kind = 'scan' AND status = 'running' AND json_extract(payload_json, '$.target_id') = ?`)
      .bind(targetId)
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async canAcquire(targetId: string, maxPerTarget: number): Promise<boolean> {
    const count = await this.count(targetId);
    return count < maxPerTarget;
  }
}

/**
 * Compatibility shim for callers that previously used the DO-based
 * `JobCoordinatorDO.acquire/release` API. The D1-backed version doesn't need
 * an explicit release — when a job's status flips to `completed`/`failed`,
 * it stops counting.
 */
export async function acquireJobSlot(
  db: D1Database,
  targetId: string,
  maxPerTarget: number,
): Promise<boolean> {
  const coordinator = new JobCoordinatorClient(db);
  return coordinator.canAcquire(targetId, maxPerTarget);
}
