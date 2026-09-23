// src/notifications/webhook.ts
import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { hmacSha256 } from "../crypto/hash.js";
import { redactSync } from "../security/redaction.js";
import { log } from "../audit/logger.js";

export async function sendGenericWebhook(env: Env, msg: NotificationMessage): Promise<boolean> {
  const integration = await env.DB
    .prepare(`SELECT config_json FROM integrations WHERE organization_id = ? AND kind = 'generic_webhook' AND enabled = 1`)
    .bind(msg.organization_id)
    .first<{ config_json: string }>();
  if (!integration) return false;
  const config = JSON.parse(integration.config_json) as { url?: string };
  if (!config.url) return false;

  // Validate the URL — only HTTPS, no private/metadata ranges
  let target: URL;
  try {
    target = new URL(config.url);
    if (target.protocol !== "https:") return false;
    if (/(^|\.)localhost$|127\.0\.0\.1|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|^10\.|^192\.168\./.test(target.hostname)) {
      log.warn("webhook.blocked_private_target", { hostname: target.hostname });
      return false;
    }
  } catch {
    return false;
  }

  const { redacted } = redactSync(JSON.stringify(msg.payload));
  const signature = await hmacSha256(env.WEBHOOK_SIGNING_SECRET, redacted);
  const resp = await fetch(target.href, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-watchtower-signature": signature,
      "x-watchtower-event": msg.payload["change_type"] as string ?? msg.payload["title"] as string ?? "alert",
    },
    body: redacted,
  });
  return resp.ok;
}
