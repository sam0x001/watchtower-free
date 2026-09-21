// src/security/redirect.ts
// Redirect destination validation — prevents open-redirect SSRF where a server
// in-scope returns a 30x to an attacker-controlled or private target.

import type { CompiledScope } from "./scope.js";
import { checkUrlInScope } from "./scope.js";
import { parseUrl } from "../utils/url.js";

export interface RedirectCheckResult {
  allowed: boolean;
  reason: string;
  finalUrl?: string;
}

export function validateRedirect(
  sourceUrl: string,
  redirectLocation: string,
  scope: CompiledScope,
): RedirectCheckResult {
  // Reject empty redirects
  if (!redirectLocation || !redirectLocation.trim()) {
    return { allowed: false, reason: "empty_location" };
  }

  const source = parseUrl(sourceUrl);
  if (!source) return { allowed: false, reason: "invalid_source" };

  // Resolve relative redirects against the source.
  let resolved: string;
  if (redirectLocation.startsWith("http://") || redirectLocation.startsWith("https://")) {
    resolved = redirectLocation;
  } else if (redirectLocation.startsWith("//")) {
    resolved = source.scheme + redirectLocation;
  } else if (redirectLocation.startsWith("/")) {
    resolved = `${source.scheme}//${source.host}${redirectLocation}`;
  } else {
    resolved = `${source.scheme}//${source.host}/${redirectLocation}`;
  }

  const check = checkUrlInScope(scope, resolved);
  if (!check.allowed) {
    return { allowed: false, reason: `redirect_out_of_scope:${check.reason}` };
  }
  return { allowed: true, reason: "ok", finalUrl: resolved };
}
