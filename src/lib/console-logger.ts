// src/lib/console-logger.ts
// Structured console logger used across the worker. Every line is JSON so
// Cloudflare Workers Logs can index it.

export interface ConsoleLogger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export function makeConsoleLogger(level: "debug" | "info" | "warn" | "error"): ConsoleLogger {
  const rank = { debug: 0, info: 1, warn: 2, error: 3 };
  return {
    debug(m, f) { if (rank[level] <= 0) console.log(JSON.stringify({ level: "debug", msg: m, ...f })); },
    info(m, f) { if (rank[level] <= 1) console.log(JSON.stringify({ level: "info", msg: m, ...f })); },
    warn(m, f) { if (rank[level] <= 2) console.warn(JSON.stringify({ level: "warn", msg: m, ...f })); },
    error(m, f) { if (rank[level] <= 3) console.error(JSON.stringify({ level: "error", msg: m, ...f })); },
  };
}

export const log = makeConsoleLogger("info");

export function newRequestId(): string {
  return `req_${crypto.randomUUID().slice(0, 12)}`;
}
