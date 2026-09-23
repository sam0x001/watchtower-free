// src/notifications/jira.ts
import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { redactSync } from "../security/redaction.js";
import { log } from "../audit/logger.js";

export async function sendJira(env: Env, msg: NotificationMessage): Promise<boolean> {
  if (!env.JIRA_API_TOKEN || !env.JIRA_BASE_URL) { log.warn("jira.disabled_no_token", {}); return false; }
  const integration = await env.DB
    .prepare(`SELECT config_json FROM integrations WHERE organization_id = ? AND kind = 'jira' AND enabled = 1`)
    .bind(msg.organization_id)
    .first<{ config_json: string }>();
  if (!integration) return false;
  const config = JSON.parse(integration.config_json) as { project_key?: string };
  if (!config.project_key) return false;

  const { redacted } = redactSync(JSON.stringify(msg.payload));
  const summary = `[${msg.severity.toUpperCase()}] ${msg.payload["title"] ?? "Watchtower alert"}`.slice(0, 200);
  const resp = await fetch(`${env.JIRA_BASE_URL}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Basic ${btoa(`watchtower-bot@${env.JIRA_BASE_URL?.replace(/^https?:\/\//, "")}:${env.JIRA_API_TOKEN}`)}`,
    },
    body: JSON.stringify({
      fields: {
        project: { key: config.project_key },
        summary,
        description: redacted,
        issuetype: { name: "Task" },
      },
    }),
  });
  return resp.ok;
}
