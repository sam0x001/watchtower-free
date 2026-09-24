// src/telegram/webhook.ts
// Telegram webhook ingress — validates the secret token, checks the user
// allowlist (AUTHORIZED_TELEGRAM_IDS env seed + allowed_users table), and
// dispatches to the command router.
//
// Anyone not on the allowlist gets a single "unauthorized" reply — exactly
// like the previous behaviour, minus the audit-log ceremony.

import type { Env } from "../env.js";
import { COMMANDS } from "../constants.js";
import { handleCommand } from "./commands.js";
import { newRequestId, log } from "../lib/console-logger.js";
import { listAllowedUsers } from "../db/queries/targets.js";

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
}

/** The effective allowlist: env seed + users added via /allow. */
export async function resolveAllowlist(env: Env): Promise<string[]> {
  const envIds = (env.AUTHORIZED_TELEGRAM_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  try {
    const dbIds = await listAllowedUsers(env.DB);
    return Array.from(new Set([...envIds, ...dbIds]));
  } catch {
    // D1 unavailable — fall back to the env allowlist only.
    return envIds;
  }
}

export async function handleTelegramWebhook(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  const secretParam = url.searchParams.get("secret");
  const xTelegramBot = request.headers.get("X-Telegram-Bot-Api-Secret-Token") ?? "";

  // Verify the secret. Telegram sends X-Telegram-Bot-Api-Secret-Token header.
  // We additionally accept a ?secret= param for router-style configuration.
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

  // Ack immediately — long work runs in waitUntil.
  ctx.waitUntil(processUpdate(update, env));
  return new Response("ok", { status: 200 });
}

async function processUpdate(update: TelegramUpdate, env: Env): Promise<void> {
  const requestId = newRequestId();
  try {
    if (!update.message?.text) return;
    const chatId = update.message.chat.id;
    const user = update.message.from;
    const text = update.message.text.trim();

    const allowed = await resolveAllowlist(env);

    // /start is always answered (a brand-new admin needs to see their ID).
    if (!text.startsWith("/start") && !allowed.includes(String(user?.id ?? ""))) {
      await sendMessage(env, chatId, "⛔ Unauthorized. Contact your Watchtower administrator.");
      return;
    }

    await handleCommand(env, {
      text,
      chatId,
      user: user && !user.is_bot ? { id: user.id, first_name: user.first_name, username: user.username } : null,
      requestId,
      allowlist: allowed,
    });
  } catch (err) {
    log.error("telegram.process_update.failed", { err: String(err), requestId });
  }
}

export async function sendMessage(
  env: Env,
  chatId: number,
  text: string,
  opts: { parseMode?: "MarkdownV2" | "HTML"; replyMarkup?: unknown } = {},
): Promise<void> {
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
      allowed_updates: ["message"],
      secret_token: env.TELEGRAM_WEBHOOK_SECRET,
    }),
  });
  await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/setMyCommands`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ commands: COMMANDS.map((c) => ({ command: c.command, description: c.description })) }),
  });
}
