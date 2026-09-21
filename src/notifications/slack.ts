// src/notifications/slack.ts
import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { redactSync } from "../security/redaction.js";
import { log } from "../audit/logger.js";

export async function sendSlack(env: Env, msg: NotificationMessage): Promise<boolean> {
  if (!env.SLACK_BOT_TOKEN) { log.warn("slack.disabled_no_token", {}); return false; }
  const { redacted } = redactSync(JSON.stringify(msg.payload));
  const text = `*[${msg.severity.toUpperCase()}]* ${redacted}`;
  // Resolve a Slack channel from integrations table
  const integration = await env.DB
    .prepare(`SELECT config_json FROM integrations WHERE organization_id = ? AND type = 'slack' AND enabled = 1`)
    .bind(msg.organization_id)
    .first<{ config_json: string }>();
  if (!integration) return false;
  const config = JSON.parse(integration.config_json) as { channel?: string };
  if (!config.channel) return false;

  const resp = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${env.SLACK_BOT_TOKEN}`,
    },
    body: JSON.stringify({ channel: config.channel, text }),
  });
  const json = (await resp.json()) as { ok: boolean; error?: string };
  return !!json.ok;
}
