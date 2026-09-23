/**
 * Watchtower — scope loader.
 *
 * Reads the authorization state for one target out of D1 and shapes it into
 * the records `evaluateScope()` consumes. Loading is deliberately separate
 * from evaluation so the evaluator stays a pure function that is easy to test
 * and impossible to make silently permissive through a database quirk.
 *
 * Everything here fails closed: unknown scope types, unknown rule kinds and
 * unreadable rows are skipped (they cannot authorize anything), and an
 * organization-level emergency stop short-circuits the whole call.
 */

import { evaluateScope, type EvaluateScopeOptions, type ScopeRecord, type ScopeRule } from './match.js';
import type { ScopeDecision } from '../types.js';
import type { ScopeStatus, ScopeType } from '../types.js';
import { emergencyStopActive, WatchtowerError } from '../lib/errors.js';

export interface ScopeLoaderEnv {
  DB: D1Database;
}

const SCOPE_TYPES: readonly ScopeType[] = [
  'domain',
  'wildcard_domain',
  'ip',
  'cidr',
  'url',
  'api',
  'repository',
  'cloud_account',
  'mobile_app',
];

const SCOPE_STATUSES: readonly ScopeStatus[] = ['active', 'paused', 'expired', 'removed'];

const RULE_KINDS = new Set([
  'port',
  'path',
  'method',
  'scheme',
  'asset_type',
  'header',
  'parameter',
  'host',
]);

/** Boolean (0/1) column decoding that never treats NULL as truthy. */
function flag(value: unknown): boolean {
  return value === 1 || value === '1' || value === true;
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}


export interface TargetAuthorizationState {
  id: string;
  status: string | null;
  authorizationStatus: string | null;
  validFrom: string | null;
  validUntil: string | null;
  passiveOnly: boolean;
  lowImpactActive: boolean;
  intrusiveEnabled: boolean;
}

export interface ScopeSnapshot {
  target: TargetAuthorizationState | null;
  scopes: ScopeRecord[];
  emergencyStop: boolean;
  /** Set when the organization row itself was unreadable; callers must refuse. */
  degraded: boolean;
}

const TARGET_SELECT = `
  SELECT t.id, t.status, t.authorization_status, t.valid_from, t.valid_until,
         t.passive_only, t.low_impact_active, t.intrusive_enabled,
         o.emergency_stop
    FROM targets t
    JOIN organizations o ON o.id = t.organization_id
   WHERE t.id = ?
`;

const SCOPES_SELECT = `
  SELECT s.id, s.organization_id, s.target_id, s.scope_type, s.value, s.display_value,
         s.status, s.is_denylist, s.include_subdomains,
         t.passive_only, t.low_impact_active, t.intrusive_enabled,
         s.valid_from, s.valid_until
    FROM scopes s
    JOIN targets t ON t.id = s.target_id
   WHERE s.target_id = ?
     AND s.status != 'removed'
   ORDER BY s.is_denylist ASC, s.id ASC
`;

const RULES_SELECT = `
  SELECT id, scope_id, rule_kind, effect, value, value_end
    FROM scope_rules
   WHERE organization_id = ?
`;

interface ScopeRowLike {
  id: unknown;
  organization_id: unknown;
  target_id: unknown;
  scope_type: unknown;
  value: unknown;
  display_value: unknown;
  status: unknown;
  is_denylist: unknown;
  include_subdomains: unknown;
  passive_only: unknown;
  low_impact_active: unknown;
  intrusive_enabled: unknown;
  valid_from: unknown;
  valid_until: unknown;
}

/** Converts one `scopes` row into a `ScopeRecord`, skipping unusable rows. */
export function mapScopeRow(row: ScopeRowLike, rules: ScopeRule[]): ScopeRecord | null {
  const id = text(row.id);
  const organizationId = text(row.organization_id);
  const targetId = text(row.target_id);
  const value = text(row.value);
  if (!id || !organizationId || !targetId || !value) return null;

  // Unknown scope type or status: this row cannot be interpreted safely, so it
  // authorizes nothing. It is dropped rather than defaulted to a permissive shape.
  if (!SCOPE_TYPES.includes(row.scope_type as ScopeType)) return null;
  if (!SCOPE_STATUSES.includes(row.status as ScopeStatus)) return null;

  return {
    id,
    organizationId,
    targetId,
    scopeType: row.scope_type as ScopeType,
    value,
    label: text(row.display_value) ?? value,
    status: row.status as ScopeStatus,
    isAllowlist: !flag(row.is_denylist),
    passiveOnly: flag(row.passive_only),
    lowImpactActive: flag(row.low_impact_active),
    intrusiveEnabled: flag(row.intrusive_enabled),
    validFrom: text(row.valid_from),
    validUntil: text(row.valid_until),
    rules,
  };
}

/** Converts one `scope_rules` row, dropping anything uninterpretable. */
export function mapRuleRow(row: {
  id: unknown;
  scope_id: unknown;
  rule_kind: unknown;
  effect: unknown;
  value: unknown;
  value_end: unknown;
}): ScopeRule | null {
  const id = text(row.id);
  const scopeId = text(row.scope_id);
  const value = text(row.value);
  const kind = text(row.rule_kind);
  const effect = text(row.effect);
  if (!id || !scopeId || !value || !kind || !effect) return null;
  if (!RULE_KINDS.has(kind)) return null;
  if (effect !== 'allow' && effect !== 'deny') return null;
  return {
    id,
    scopeId,
    ruleKind: kind as ScopeRule['ruleKind'],
    effect,
    value,
    valueEnd: text(row.value_end),
  };
}

/**
 * Loads everything the scope gate needs for one target in three queries.
 *
 * Throws `scope_missing` when the target itself does not exist: a scan must
 * never proceed on the assumption that an unknown target is authorized.
 */
export async function loadScopeSnapshot(env: ScopeLoaderEnv, targetId: string): Promise<ScopeSnapshot> {
  const targetRow = await env.DB.prepare(TARGET_SELECT).bind(targetId).first<{
    id: string;
    status: string | null;
    authorization_status: string | null;
    valid_from: string | null;
    valid_until: string | null;
    passive_only: number | null;
    low_impact_active: number | null;
    intrusive_enabled: number | null;
    emergency_stop: number | null;
  }>();

  if (!targetRow) {
    throw new WatchtowerError('scope_missing', `Target ${targetId} does not exist.`, {
      details: { targetId },
    });
  }

  const scopeRows = await env.DB.prepare(SCOPES_SELECT).bind(targetId).all<ScopeRowLike>();
  const rawScopes = scopeRows.results ?? [];

  const organizationId = text(rawScopes[0]?.organization_id) ?? null;
  const rulesByScope = new Map<string, ScopeRule[]>();
  if (organizationId) {
    const ruleRows = await env.DB.prepare(RULES_SELECT).bind(organizationId).all<{
      id: unknown;
      scope_id: unknown;
      rule_kind: unknown;
      effect: unknown;
      value: unknown;
      value_end: unknown;
    }>();
    for (const row of ruleRows.results ?? []) {
      const mapped = mapRuleRow(row);
      if (!mapped) continue;
      const bucket = rulesByScope.get(mapped.scopeId);
      if (bucket) bucket.push(mapped);
      else rulesByScope.set(mapped.scopeId, [mapped]);
    }
  }

  const scopes: ScopeRecord[] = [];
  for (const row of rawScopes) {
    const mapped = mapScopeRow(row, rulesByScope.get(String(row.id)) ?? []);
    if (mapped) scopes.push(mapped);
  }

  return {
    target: {
      id: String(targetRow.id),
      status: text(targetRow.status),
      authorizationStatus: text(targetRow.authorization_status),
      validFrom: text(targetRow.valid_from),
      validUntil: text(targetRow.valid_until),
      passiveOnly: flag(targetRow.passive_only),
      lowImpactActive: flag(targetRow.low_impact_active),
      intrusiveEnabled: flag(targetRow.intrusive_enabled),
    },
    scopes,
    // Unreadable `emergency_stop` must behave as "stopped", never as "running".
    emergencyStop: targetRow.emergency_stop === null ? true : flag(targetRow.emergency_stop),
    degraded: false,
  };
}

/**
 * Gate helper used by every caller about to touch the network: loads the
 * snapshot, runs `evaluateScope` and throws a typed refusal when denied.
 */
export async function assertInScope(
  env: ScopeLoaderEnv,
  targetId: string,
  asset: string,
  options: EvaluateScopeOptions = {},
): Promise<ScopeDecision> {
  const snapshot = await loadScopeSnapshot(env, targetId);
  const targetOption = options.target ?? (snapshot.target as EvaluateScopeOptions['target']);
  const decision = evaluateScope(asset, snapshot.scopes, {
    ...options,
    emergencyStop: snapshot.emergencyStop || options.emergencyStop === true,
    target: targetOption,
  });
  if (!decision.allowed) {
    if (snapshot.emergencyStop) {
      throw emergencyStopActive(`target ${targetId}`);
    }
    throw new WatchtowerError(
      decision.validation === 'expired' ? 'scope_expired' : 'out_of_scope',
      decision.reason,
      { details: { targetId, asset, validation: decision.validation } },
    );
  }
  return decision;
}

