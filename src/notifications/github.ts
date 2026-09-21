// src/notifications/github.ts
import type { Env } from "../env.js";
import type { NotificationMessage } from "../types.js";
import { redactSync } from "../security/redaction.js";
import { log } from "../audit/logger.js";

export async function sendGithub(env: Env, msg: NotificationMessage): Promise<boolean> {
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) { log.warn("github.disabled_no_config", {}); return false; }
  const { redacted } = redactSync(JSON.stringify(msg.payload));
  const title = `[${msg.severity.toUpperCase()}] ${msg.payload["title"] ?? "Watchtower finding"}`.slice(0, 200);
  const url = `https://api.github.com/repos/${env.GITHUB_REPO}/issues`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "accept": "application/vnd.github+json",
    },
    body: JSON.stringify({
      title,
      body: redacted,
      labels: [`severity:${msg.severity}`, "watchtower"],
    }),
  });
  return resp.ok;
}
