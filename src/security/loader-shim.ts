// Re-export scope loader primitives at the legacy security/ path.
export { loadScopeSnapshot, assertInScope } from "../scope/loader.js";
export type { ScopeSnapshot, TargetAuthorizationState, ScopeLoaderEnv } from "../scope/loader.js";
