// src/index.ts
// Watchtower — main Worker entry point (FREE TIER version).
//
// Exports:
//   - default fetch handler — routes /telegram, /v1/*, /health
//   - scheduled handler — single cron trigger (5-min interval) that dispatches
//     scan jobs + notification jobs from the D1-backed job_queue
//
// Free-tier constraints:
//   - NO Durable Objects (all replaced with D1 row state)
//   - NO Queues (all replaced with D1 job_queue table)
//   - 1 Cron Trigger (5-min interval with internal time-of-day dispatch)
//   - 10ms CPU per invocation (work runs in ctx.waitUntil())
//   - 100k Worker requests/day

import type { Env } from "./env.js";
import { handleTelegramWebhook } from "./telegram/webhook.js";
import { routeApi } from "./api/router.js";
import { handleScheduled } from "./cron/handler.js";
import { makeConsoleLogger } from "./audit/logger.js";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const log = makeConsoleLogger("info");

    const url = new URL(request.url);

    // ---- Health & readiness -----------------------------------------------
    if (url.pathname === "/health" || url.pathname === "/") {
      return new Response(JSON.stringify({
        status: "ok",
        service: "watchtower",
        version: "3.0.0-free",
        tier: "free",
        env: env.WATCHTOWER_ENV,
        time: new Date().toISOString(),
      }), { headers: { "content-type": "application/json" } });
    }

    // ---- Telegram webhook -------------------------------------------------
    if (url.pathname === "/telegram" || url.pathname === "/telegram/") {
      return handleTelegramWebhook(request, env, ctx, log);
    }

    // ---- REST API ---------------------------------------------------------
    if (url.pathname.startsWith("/v1/") || url.pathname === "/v1") {
      return routeApi(request, env, ctx);
    }

    // ---- 404 --------------------------------------------------------------
    return new Response(JSON.stringify({ ok: false, error: { code: "not_found", message: `No route for ${url.pathname}` } }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleScheduled(controller, env, ctx);
  },
} satisfies ExportedHandler<Env>;
