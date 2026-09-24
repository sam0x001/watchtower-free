// src/index.ts
// Watchtower — Worker entry point (FREE TIER build).
//
// Routes:
//   GET /            → service banner (JSON)
//   GET /health      → health probe (JSON)
//   POST /telegram   → Telegram webhook (secret-token validated)
//   anything else    → 404
//
// scheduled → single cron trigger (every 5 minutes) that drives the whole
//             pipeline: notification dispatch, scan jobs, rescan scheduling and
//             retention.
//
// Free-tier constraints respected here: no Durable Objects, no Queues, one
// cron trigger, no REST API.

import type { Env } from "./env.js";
import { handleTelegramWebhook } from "./telegram/webhook.js";
import { handleScheduled } from "./cron/handler.js";
import { log } from "./lib/console-logger.js";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // ---- Health & readiness -----------------------------------------------
    if (url.pathname === "/" || url.pathname === "/health") {
      return json({
        status: "ok",
        service: "watchtower",
        version: "4.0.0-free",
        tier: "free",
        env: env.WATCHTOWER_ENV,
        time: new Date().toISOString(),
      });
    }

    // ---- Telegram webhook -------------------------------------------------
    if (url.pathname === "/telegram" || url.pathname === "/telegram/") {
      return handleTelegramWebhook(request, env, ctx);
    }

    // ---- 404 --------------------------------------------------------------
    log.debug("http.not_found", { path: url.pathname });
    return json({ ok: false, error: { code: "not_found", message: `No route for ${url.pathname}` } }, 404);
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleScheduled(controller, env, ctx);
  },
} satisfies ExportedHandler<Env>;

