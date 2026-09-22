// src/telegram/webhook.ts
// Telegram webhook ingress — validates the secret token, parses the update,
// dispatches to the command router, and acks Telegram quickly.

import type { Env } from "../env.js";
import type { ConsoleLogger } from "../audit/logger.js";
import { verifyWebhookSignature } from "../crypto/hmac.js";
import { COMMANDS } from "../constants.js";
import { handleCommand } from "./commands.js";
import { newRequestId } from "../audit/logger.js";
import { D1AuditLogger } from "../audit/logger.js";

const TELEGRAM_API = "https://api.telegram.org";

export interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    chat: { id: number; type: string; title?: string };
    from?: { id: number; is_bot: boolean; first_name?: string; last_name?: string; username?: string };
    text?: string;
    date: number;
  };
  callback_query?: {
    id: string;
    from: { id: number; is_bot: boolean; first_name?: string; username?: string };
    message: { message_id: number; chat: { id: number; type: string } };
    data: string;
  };
}

export async function handleTelegramWebhook(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  log: ConsoleLogger,
): Promise<Response> {
  const url = new URL(request.url);
  const secretParam = url.searchParams.get("secret");
  const xTelegramBot = request.headers.get("X-Telegram-Bot-Api-Secret-Token") ?? "";

  // Verify the secret. Telegram sends X-Telegram-Bot-Api-Secret-Token header.
  // We additionally accept a ?secret= path param for router-style configuration.
  if (env.TELEGRAM_WEBHOOK_SECRET) {
    if (secretParam !== env.TELEGRAM_WEBHOOK_SECRET && xTelegramBot !== env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }
  }

  let update: TelegramUpdate;
  try {
    update = (await request.json()) as TelegramUpdate;
  } catch {
    return new Response("Bad Request", { status: 400 });
  }

  // Ack immediately — long work is moved to waitUntil and/or queues.
  ctx.waitUntil(processUpdate(update, env, request, log));

  // Register the command list on first webhook call (best-effort, idempotent)
  return new Response("ok", { status: 200 });
}

async function processUpdate(
  update: TelegramUpdate,
  env: Env,
  request: Request,
  log: ConsoleLogger,
): Promise<void> {
  const requestId = newRequestId();
  const audit = new D1AuditLogger(env.DB);
  try {
    if (update.message?.text) {
      const chatId = update.message.chat.id;
      const user = update.message.from;
      const text = update.message.text.trim();
      const allowedIds = (env.AUTHORIZED_TELEGRAM_IDS ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const isBootstrap = allowedIds.length > 0 && user ? allowedIds.includes(String(user.id)) : false;

      // `/start` is always allowed so a brand-new admin can bootstrap
      if (!text.startsWith("/start") && !isBootstrap) {
        await sendMessage(env, chatId, "⛔ Unauthorized. Contact your Watchtower administrator.");
        await audit.log({
          timestamp: new Date().toISOString(),
          user_id: null,
          telegram_id: user ? String(user.id) : null,
          actor_kind: "telegram",
          organization_id: null,
          action: "telegram.command.unauthorized",
          target_id: null,
          scope_id: null,
          job_id: null,
          scanner: null,
          args_redacted: JSON.stringify({ command: text }),
          result: "denied",
          error: "User not in AUTHORIZED_TELEGRAM_IDS",
          ip: request.headers.get("cf-connecting-ip"),
          request_id: requestId,
        });
        return;
      }
      await handleCommand(env, {
        text,
        chatId,
        user: user ? { id: user.id, first_name: user.first_name, username: user.username } : null,
        requestId,
        audit,
        log,
      });
    } else if (update.callback_query) {
      const cq = update.callback_query;
      await handleCallback(env, cq, requestId, audit, log);
    }
  } catch (err) {
    log.error("telegram.process_update.failed", { err: String(err), requestId });
    await audit.log({
      timestamp: new Date().toISOString(),
      user_id: null,
      telegram_id: update.message?.from ? String(update.message.from.id) : null,
      actor_kind: "telegram",
      organization_id: null,
      action: "telegram.process_update",
      target_id: null,
      scope_id: null,
      job_id: null,
      scanner: null,
      args_redacted: JSON.stringify({ update_id: update.update_id }),
      result: "failure",
      error: String(err),
      ip: request.headers.get("cf-connecting-ip"),
      request_id: requestId,
    });
  }
}

async function handleCallback(
  env: Env,
  cq: NonNullable<TelegramUpdate["callback_query"]>,
  requestId: string,
  audit: D1AuditLogger,
  log: ConsoleLogger,
): Promise<void> {
  // Callback format: "finding:verify:FND-1234" etc.
  const data = cq.data;
  const [kind, action, id] = data.split(":", 3);
  await audit.log({
    timestamp: new Date().toISOString(),
    user_id: null,
    telegram_id: String(cq.from.id),
    actor_kind: "telegram",
    organization_id: null,
    action: `telegram.callback.${kind}.${action}`,
    target_id: null,
    scope_id: null,
    job_id: null,
    scanner: null,
    args_redacted: JSON.stringify({ id }),
    result: "success",
    error: null,
    ip: null,
    request_id: requestId,
  });

  // Answer the callback to remove the spinner
  await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ callback_query_id: cq.id }),
  });

  if (kind === "finding") {
    await sendMessage(env, cq.message.chat.id, `✅ Received ${action} for finding ${id}. Use the API or run /finding_${action} to complete.`);
  }
}

export async function sendMessage(env: Env, chatId: number, text: string, opts: { parseMode?: "MarkdownV2" | "HTML"; replyMarkup?: unknown } = {}): Promise<void> {
  if (text.length > 4096) text = text.slice(0, 4090) + "\n...";
  await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: opts.parseMode,
      reply_markup: opts.replyMarkup,
      disable_web_page_preview: true,
    }),
  });
}

export async function setWebhook(env: Env, publicUrl: string): Promise<void> {
  await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      url: `${publicUrl}/telegram?secret=${env.TELEGRAM_WEBHOOK_SECRET}`,
      allowed_updates: ["message", "callback_query"],
      secret_token: env.TELEGRAM_WEBHOOK_SECRET,
    }),
  });
  await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/setMyCommands`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ commands: COMMANDS.map((c) => ({ command: c.command, description: c.description })) }),
  });
}
