// src/notifications/email.ts
import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { redactSync } from "../security/redaction.js";
import { log } from "../audit/logger.js";

export async function sendEmail(env: Env, msg: NotificationMessage): Promise<boolean> {
  if (!env.SENDGRID_API_KEY || !env.SENDGRID_FROM) { log.warn("email.disabled_no_config", {}); return false; }
  const integration = await env.DB
    .prepare(`SELECT config_json FROM integrations WHERE organization_id = ? AND kind = 'email' AND enabled = 1`)
    .bind(msg.organization_id)
    .first<{ config_json: string }>();
  if (!integration) return false;
  const config = JSON.parse(integration.config_json) as { recipients?: string[] };
  if (!config.recipients || config.recipients.length === 0) return false;

  const { redacted } = redactSync(JSON.stringify(msg.payload));
  const subject = `[Watchtower] [${msg.severity.toUpperCase()}] ${msg.payload["title"] ?? "Alert"}`;
  const resp = await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${env.SENDGRID_API_KEY}`,
    },
    body: JSON.stringify({
      personalizations: [{ to: config.recipients.map((email) => ({ email })) }],
      from: { email: env.SENDGRID_FROM },
      subject,
      content: [{ type: "text/plain", value: redacted }],
    }),
  });
  return resp.ok;
}
