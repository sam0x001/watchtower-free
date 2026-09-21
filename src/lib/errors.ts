/**
 * Watchtower error taxonomy.
 *
 * Every error carries a stable machine-readable `code` (surfaced in the REST
 * API, structured logs and audit trail) plus an HTTP status hint. Errors are
 * deliberately explicit: security-relevant refusals must never be silently
 * swallowed by a generic catch block.
 */

export type WatchtowerErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'validation_error'
  | 'conflict'
  | 'rate_limited'
  | 'idempotency_conflict'
  | 'scope_missing'
  | 'scope_expired'
  | 'scope_paused'
  | 'scope_ambiguous'
  | 'scope_violation'
  | 'out_of_scope'
  | 'authorization_missing'
  | 'authorization_expired'
  | 'authorization_revoked'
  | 'approval_required'
  | 'emergency_stop'
  | 'module_disabled'
  | 'disabled_by_program_rules'
  | 'ssrf_blocked'
  | 'redirect_blocked'
  | 'dns_rebinding_detected'
  | 'payload_too_large'
  | 'timeout'
  | 'dependency_failure'
  | 'provider_error'
  | 'runner_error'
  | 'signature_invalid'
  | 'replay_detected'
  | 'internal_error';

const STATUS_BY_CODE: Record<WatchtowerErrorCode, number> = {
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  validation_error: 400,
  conflict: 409,
  rate_limited: 429,
  idempotency_conflict: 409,
  scope_missing: 409,
  scope_expired: 409,
  scope_paused: 409,
  scope_ambiguous: 409,
  scope_violation: 403,
  out_of_scope: 403,
  authorization_missing: 409,
  authorization_expired: 409,
  authorization_revoked: 409,
  approval_required: 409,
  emergency_stop: 423,
  module_disabled: 403,
  disabled_by_program_rules: 403,
  ssrf_blocked: 403,
  redirect_blocked: 403,
  dns_rebinding_detected: 403,
  payload_too_large: 413,
  timeout: 504,
  dependency_failure: 502,
  provider_error: 502,
  runner_error: 502,
  signature_invalid: 401,
  replay_detected: 409,
  internal_error: 500,
};

/**
 * Errors where retrying the identical, idempotent operation may legitimately
 * succeed. Non-retryable errors must never be requeued blindly: a scope
 * violation that is retried is still a scope violation.
 */
const RETRYABLE = new Set<WatchtowerErrorCode>([
  'rate_limited',
  'timeout',
  'dependency_failure',
  'provider_error',
  'runner_error',
  'internal_error',
]);

export interface WatchtowerErrorOptions {
  /** Extra, non-sensitive, machine-readable context for logs and audit rows. */
  readonly details?: Record<string, unknown>;
  /** Sanitised message that is safe to show to an operator. */
  readonly userMessage?: string;
  readonly cause?: unknown;
}

export class WatchtowerError extends Error {
  readonly code: WatchtowerErrorCode;
  readonly status: number;
  readonly details: Record<string, unknown>;
  readonly userMessage: string;
  readonly retryable: boolean;

  constructor(code: WatchtowerErrorCode, message: string, options: WatchtowerErrorOptions = {}) {
    super(message);
    this.name = 'WatchtowerError';
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.details = options.details ?? {};
    this.userMessage = options.userMessage ?? message;
    this.retryable = RETRYABLE.has(code);
    if (options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      userMessage: this.userMessage,
      status: this.status,
      retryable: this.retryable,
      details: this.details,
    };
  }
}

// -- Convenience constructors used across the codebase -----------------------

export const unauthorized = (message = 'Authentication required.') =>
  new WatchtowerError('unauthorized', message);

export const forbidden = (message = 'Not permitted.', options?: WatchtowerErrorOptions) =>
  new WatchtowerError('forbidden', message, options);

export const notFound = (what: string) => new WatchtowerError('not_found', `${what} not found.`);

export const validationError = (message: string, details?: Record<string, unknown>) =>
  new WatchtowerError('validation_error', message, { details });

export const approvalRequired = (message: string, details?: Record<string, unknown>) =>
  new WatchtowerError('approval_required', message, { details });

export const emergencyStopActive = (scope: string) =>
  new WatchtowerError(
    'emergency_stop',
    `Emergency stop is active (${scope}). All scanning is halted until an operator runs /resume.`,
    { details: { emergencyStopScope: scope } },
  );

export const outOfScope = (asset: string, reason: string) =>
  new WatchtowerError('out_of_scope', `Asset ${asset} is not in authorized scope: ${reason}`, {
    details: { asset, reason },
  });

export const ssrfBlocked = (target: string, reason: string) =>
  new WatchtowerError('ssrf_blocked', `Blocked request to ${target}: ${reason}`, {
    details: { target, reason },
  });

export const providerError = (provider: string, message: string, details?: Record<string, unknown>) =>
  new WatchtowerError('provider_error', `Provider ${provider} failed: ${message}`, {
    details: { provider, ...details },
  });

export const runnerError = (message: string, details?: Record<string, unknown>) =>
  new WatchtowerError('runner_error', message, { details });

/**
 * Converts any thrown value into a safe, serialisable shape. Never leaks the
 * original stack into operator-facing output.
 */
export const toSafeError = (error: unknown): {
  code: WatchtowerErrorCode;
  message: string;
  userMessage: string;
  details: Record<string, unknown>;
} => {
  if (error instanceof WatchtowerError) {
    return {
      code: error.code,
      message: error.message,
      userMessage: error.userMessage,
      details: error.details,
    };
  }
  return {
    code: 'internal_error',
    message: error instanceof Error ? error.message : 'Unknown error',
    userMessage: 'An internal error occurred. Reference the correlation ID in the logs.',
    details: {},
  };
};


export const isRetryable = (error: unknown): boolean =>
  error instanceof WatchtowerError && error.retryable;

export const isWatchtowerError = (error: unknown): error is WatchtowerError =>
  error instanceof WatchtowerError;
