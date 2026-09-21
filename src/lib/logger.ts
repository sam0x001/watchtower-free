/**
 * Structured JSON logging.
 *
 * Every log line is a single JSON object so Cloudflare Workers Logs /
 * Logpush can index it. A redaction pass runs over all fields so that a
 * credential can never reach the log sink even if a caller passes one by
 * accident.
 */

import { redactDeep, redactString } from './redact.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export interface LoggerContext {
  requestId?: string;
  correlationId?: string;
  organizationId?: string;
  targetId?: string;
  userId?: string;
  telegramUserId?: string;
  jobId?: string;
  scanId?: string;
  component?: string;
}

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  child(context: LoggerContext): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  context?: LoggerContext;
  /** Overridable sink, used by tests. */
  sink?: (line: string) => void;
}

export const TRUNCATED = '[TRUNCATED]';
const MAX_FIELD_STRING = 4000;

function truncateDeep(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[DEPTH_LIMIT]';
  if (typeof value === 'string') {
    return value.length > MAX_FIELD_STRING
      ? `${value.slice(0, MAX_FIELD_STRING)}${TRUNCATED}`
      : value;
  }
  if (Array.isArray(value)) {
    // Bound array rendering so a large certificate or JS dataset cannot be
    // logged in full.
    const head = value.slice(0, 50).map((entry) => truncateDeep(entry, depth + 1));
    if (value.length > 50) head.push(`[${value.length - 50} more items]`);
    return head;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = truncateDeep(entry, depth + 1);
    }
    return out;
  }
  return value;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? 'info';
  const baseContext = options.context ?? {};
  const sink = options.sink ?? ((line: string) => console.log(line));

  const emit = (
    target: LogLevel,
    event: string,
    fields: Record<string, unknown> | undefined,
    context: LoggerContext,
  ): void => {
    if (LEVEL_ORDER[target] < LEVEL_ORDER[level]) return;

    const record: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level: target,
      event: redactString(event),
      service: 'watchtower',
      ...context,
      ...(fields ? (truncateDeep(redactDeep(fields)) as Record<string, unknown>) : {}),
    };

    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      line = JSON.stringify({
        ts: record.ts,
        level: target,
        event,
        serialization_error: true,
      });
    }
    sink(line);
  };

  const make = (context: LoggerContext): Logger => ({
    debug: (event, fields) => emit('debug', event, fields, context),
    info: (event, fields) => emit('info', event, fields, context),
    warn: (event, fields) => emit('warn', event, fields, context),
    error: (event, fields) => emit('error', event, fields, context),
    child: (extra) => make({ ...context, ...extra }),
  });

  return make(baseContext);
}

export function levelFromEnv(value: string | undefined): LogLevel {
  if (value === 'debug' || value === 'info' || value === 'warn' || value === 'error') {
    return value;
  }
  return 'info';
}
