// src/security/scope.ts
// Re-export shim. The scope engine lives in `src/scope/match.ts` +
// `src/scope/index.ts`; this keeps legacy import paths working.

export {
  compileScope,
  checkHostInScope,
  checkUrlInScope,
  isScopeExpired,
  isWildcardPattern,
  evaluateScope,
  parseAsset,
  isBlockedIp,
  isWildcardTooBroad,
} from "../scope/index.js";

export type {
  CompiledScope,
  ScopeCheckResult,
  CheckHostOptions,
} from "../scope/index.js";

export type { ScopeRecord, ScopeRule, ParsedAsset, EvaluateScopeOptions } from "../scope/match.js";
