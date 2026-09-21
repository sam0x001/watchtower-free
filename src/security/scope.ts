// src/security/scope.ts
// Backwards-compatibility re-export. The canonical scope engine now lives in
// `src/scope/match.ts` + `src/scope/loader.ts` (mirrored from watchtower1's
// more thorough implementation, with salted fingerprints and fail-closed
// loader). This file just re-exports the public API at the legacy import path
// so existing modules don't need their imports rewritten.

export {
  compileScope,
  loadCompiledScope,
  checkHostInScope,
  checkUrlInScope,
  isScopeExpired,
  scopeExpiringSoon,
  isWildcardPattern,
  evaluateScope,
  parseAsset,
  isBlockedIp,
  isWildcardTooBroad,
  loadScopeSnapshot,
  assertInScope,
} from "../scope/index.js";

export type {
  CompiledScope,
  ScopeCheckResult,
  CheckHostOptions,
} from "../scope/index.js";

export type { ScopeRecord, ScopeRule, ParsedAsset, EvaluateScopeOptions } from "../scope/match.js";
export type { ScopeSnapshot, TargetAuthorizationState, ScopeLoaderEnv } from "../scope/loader.js";
