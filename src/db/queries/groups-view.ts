// src/db/queries/groups-view.ts
// Bulk read helpers for /target-info and /list. One query per concern for the
// whole group instead of N+1 lookups per member domain.

import { FEATURES, FEATURE_KEYS, type FeatureMap } from "./features.js";

export interface TargetOverview {
  /** target_id → ISO timestamp of its most recent scan, or null. */
  lastScan: Map<string, string | null>;
  /** target_id → number of active exclusion (denylist) scope rows. */
  exclusions: Map<string, number>;
  /** target_id → effective feature map (defaults applied). */
  features: Map<string, FeatureMap>;
}

/** Last `scans.created_at` per target id (targets without scans → null). */
export async function lastScansByTarget(
  db: D1Database,
  targetIds: string[],
): Promise<Map<string, string | null>> {
  const out = new Map<string, string | null>();
  for (const id of targetIds) out.set(id, null);
  if (targetIds.length === 0) return out;

  const rows = await db
    .prepare(
      `SELECT target_id, MAX(created_at) AS last_scan FROM scans
        WHERE target_id IN (${targetIds.map(() => "?").join(",")})
        GROUP BY target_id`,
    )
    .bind(...targetIds)
    .all<{ target_id: string; last_scan: string }>();
  for (const r of rows.results ?? []) out.set(r.target_id, r.last_scan);
  return out;
}

/** Active denylist scope rows per target (exclusions). */
export async function exclusionCountsByTargets(
  db: D1Database,
  targetIds: string[],
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const id of targetIds) out.set(id, 0);
  if (targetIds.length === 0) return out;

  const rows = await db
    .prepare(
      `SELECT target_id, COUNT(*) AS n FROM scopes
        WHERE is_denylist = 1 AND status = 'active'
          AND target_id IN (${targetIds.map(() => "?").join(",")})
        GROUP BY target_id`,
    )
    .bind(...targetIds)
    .all<{ target_id: string; n: number }>();
  for (const r of rows.results ?? []) out.set(r.target_id, r.n);
  return out;
}

/**
 * Effective feature map per target. Reads every stored override for the set in
 * ONE query and applies defaults in memory (mirrors getFeatureMap).
 */
export async function featureCountsByTargets(
  db: D1Database,
  targetIds: string[],
): Promise<Map<string, FeatureMap>> {
  const overrides = new Map<string, Map<string, number>>();
  const base = (): FeatureMap => {
    const m = {} as FeatureMap;
    for (const key of FEATURE_KEYS) m[key] = FEATURES[key]!.defaultOn;
    return m;
  };

  const out = new Map<string, FeatureMap>();
  for (const id of targetIds) out.set(id, base());
  if (targetIds.length === 0) return out;

  const rows = await db
    .prepare(
      `SELECT target_id, feature_key, enabled FROM target_features
        WHERE target_id IN (${targetIds.map(() => "?").join(",")})`,
    )
    .bind(...targetIds)
    .all<{ target_id: string; feature_key: string; enabled: number }>();

  for (const r of rows.results ?? []) {
    let perTarget = overrides.get(r.target_id);
    if (!perTarget) {
      perTarget = new Map();
      overrides.set(r.target_id, perTarget);
    }
    perTarget.set(r.feature_key, r.enabled);
  }

  for (const [targetId, perTarget] of overrides) {
    const map = out.get(targetId)!;
    for (const [key, enabled] of perTarget) {
      if ((FEATURE_KEYS as string[]).includes(key)) {
        (map as Record<string, boolean>)[key] = enabled === 1;
      }
    }
  }
  return out;
}

/** Count of ON features in a map (used by the boards). */
export function countEnabled(map: FeatureMap): number {
  return FEATURE_KEYS.reduce((n, key) => n + (map[key] ? 1 : 0), 0);
}

/** Aggregate the three maps above in one call. */
export async function loadTargetOverview(
  db: D1Database,
  targetIds: string[],
): Promise<TargetOverview> {
  const [lastScan, exclusions, features] = await Promise.all([
    lastScansByTarget(db, targetIds),
    exclusionCountsByTargets(db, targetIds),
    featureCountsByTargets(db, targetIds),
  ]);
  return { lastScan, exclusions, features };
}
