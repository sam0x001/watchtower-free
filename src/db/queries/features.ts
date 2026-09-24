// src/db/queries/features.ts
// Per-target monitoring feature toggles (migrations/0005_target_features.sql).
//
// A target has eight independent switches. Missing rows mean "default", so a
// freshly added target needs no seeding and newly introduced keys keep working
// on old databases. The scan runner reads the map once per pass and skips the
// disabled phases entirely — disabled work costs zero requests.

export type FeatureKey =
  | "subdomain_enum"
  | "dns_brute"
  | "js_changes"
  | "fuzz_files"
  | "deep_fuzz"
  | "status_watch"
  | "port_watch"
  | "nuclei";

export interface FeatureMeta {
  label: string;
  blurb: string;
  /** Effective value when no row exists for (target, key). */
  defaultOn: boolean;
}

export const FEATURES: Record<FeatureKey, FeatureMeta> = {
  subdomain_enum: {
    label: "Subdomain enumeration",
    blurb: "CT logs + DNS records (passive)",
    defaultOn: true,
  },
  dns_brute: {
    label: "DNS brute force",
    blurb: "resolve common subdomain prefixes",
    defaultOn: true,
  },
  js_changes: {
    label: "JS file changes",
    blurb: "discover + hash + diff JavaScript files",
    defaultOn: true,
  },
  fuzz_files: {
    label: "Common file fuzzing",
    blurb: "probe .env/.git/backups/swagger on all assets",
    defaultOn: true,
  },
  deep_fuzz: {
    label: "Deep fuzz on new assets",
    blurb: "deeper pass on freshly discovered hosts",
    defaultOn: true,
  },
  status_watch: {
    label: "Status-code watch",
    blurb: "alert on 404/5xx/redirect changes",
    defaultOn: true,
  },
  port_watch: {
    label: "Open ports",
    blurb: "watch 14 common HTTP(S) ports",
    defaultOn: true,
  },
  nuclei: {
    label: "Nuclei templates",
    blurb: "needs an external runner (off by default)",
    defaultOn: false,
  },
};

export const FEATURE_KEYS = Object.keys(FEATURES) as FeatureKey[];

export type FeatureMap = Record<FeatureKey, boolean>;

/** Effective toggle map for a target (defaults applied for untouched keys). */
export async function getFeatureMap(db: D1Database, targetId: string): Promise<FeatureMap> {
  const map = {} as FeatureMap;
  for (const key of FEATURE_KEYS) map[key] = FEATURES[key]!.defaultOn;

  const rows = await db
    .prepare(`SELECT feature_key, enabled FROM target_features WHERE target_id = ?`)
    .bind(targetId)
    .all<{ feature_key: string; enabled: number }>();

  for (const row of rows.results ?? []) {
    if ((FEATURE_KEYS as string[]).includes(row.feature_key)) {
      (map as Record<string, boolean>)[row.feature_key] = row.enabled === 1;
    }
  }
  return map;
}

/** Persist one toggle. Unknown keys are rejected by the table CHECK. */
export async function setFeature(
  db: D1Database,
  targetId: string,
  key: FeatureKey,
  enabled: boolean,
  updatedBy: string | null,
): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO target_features (target_id, feature_key, enabled, updated_by, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(target_id, feature_key) DO UPDATE SET
         enabled = excluded.enabled,
         updated_by = excluded.updated_by,
         updated_at = excluded.updated_at`,
    )
    .bind(targetId, key, enabled ? 1 : 0, updatedBy, now)
    .run();
}
