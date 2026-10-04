// src/telegram/commands.ts
// Command router — the entire bot surface:
//   /start /help /target_add /target_info /add /remove /list /exclude
//   /scan /feature /allow /disallow
//
// Note on names: Telegram command menus only allow [a-zA-Z0-9_] — a "-"
// breaks setMyCommands, so underscore is the canonical spelling everywhere
// the bot shows a command. parseCommand still folds "-" to "_", so anyone
// who types the hyphenated form from an old message still lands on the
// right handler.

import type { Env } from "../env.js";
import { sendMessage } from "./webhook.js";
import { messages } from "./messages.js";
import { normalizeDomain } from "../utils/domain.js";
import type { ScopeType } from "../types.js";
import {
  getTargetByNameOrId,
  listTargets,
  listScopeEntries,
  createTarget,
  deleteTarget,
  deleteTargetGroup,
  insertScopeEntry,
  removeScopeEntry,
  addAllowedUser,
  removeAllowedUser,
  createTargetGroup,
  getTargetGroupByNameOrId,
  listTargetGroups,
  listTargetsByGroup,
  setTargetGroup,
} from "../db/queries/targets.js";
import {
  SCAN_GROUP_BATCH,
  clearRemoveConfirmation,
  clearScanContinuation,
  readRemoveConfirmation,
  readScanContinuation,
  saveRemoveConfirmation,
  saveScanContinuation,
} from "./pending.js";
import { FEATURES, FEATURE_KEYS, getFeatureMap, setFeature, type FeatureKey } from "../db/queries/features.js";
import { loadTargetOverview, countEnabled } from "../db/queries/groups-view.js";

/** Compact "3m ago" / "5h ago" style timestamp for the boards. */
function relTime(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "just now";
  const min = Math.floor(ms / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
import { runInitialScanInline } from "../queues/scan-runner.js";

export interface CommandContext {
  text: string;
  chatId: number;
  user: { id: number; first_name?: string; username?: string } | null;
  requestId: string;
  /** Effective allowlist at dispatch time (env seed + allowed_users). */
  allowlist: string[];
}

interface ParsedCommand {
  command: string;
  args: string[];
}

// Telegram sends "/cmd" or "/cmd@botname"; normalize both.
function parseCommand(text: string): ParsedCommand {
  const trimmed = text.trim().replace(/^@\w+\s+/, "").replace(/^\//, "");
  const [first, ...rest] = trimmed.split(/\s+/);
  if (!first) return { command: "help", args: [] };
  return { command: first.toLowerCase().replace(/-/g, "_"), args: rest };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Delete a category and every domain filed under it, returning how many
 * domains were destroyed.
 *
 * Each member is deleted through `deleteTarget` (the same path as /remove on a
 * single domain) so all their scopes/assets/scans/findings cascade exactly as
 * they would one at a time, then the now-empty category row goes too.
 *
 * Exported for tests: this is the destructive half of /remove <category>.
 */
export async function deleteGroupAndMembers(env: Env, groupId: string): Promise<number> {
  const members = await listTargetsByGroup(env.DB, groupId);
  let deleted = 0;
  for (const member of members) {
    await deleteTarget(env.DB, member.id);
    deleted++;
  }
  await deleteTargetGroup(env.DB, groupId);
  return deleted;
}

/**
 * `/scan <category>` — run the inline discovery pass for the category's member
 * domains, one bounded batch at a time.
 *
 * Each member costs several third-party CT/DNS calls, so at most
 * SCAN_GROUP_BATCH run inline per command; the remainder is reported with a
 * token to continue. Every domain scanned here is also picked up by the normal
 * cron schedule, so continuation is a convenience, not a requirement.
 */
async function scanGroup(env: Env, ctx: CommandContext, group: { id: string; name: string }): Promise<void> {
  const members = await listTargetsByGroup(env.DB, group.id);
  if (members.length === 0) {
    await sendMessage(env, ctx.chatId,
      `📂 <b>${escapeHtml(group.name)}</b> has no domains yet.\n` +
      `Add one with <code>/add example.com ${escapeHtml(group.name)}</code>.`,
      { parseMode: "HTML" });
    return;
  }

  // A second `/scan <category>` continues where the first left off.
  const previous = await readScanContinuation(env, ctx.chatId, group.id);
  const paused = members.filter((m) => m.paused);
  const queue = (previous?.pending
    ? members.filter((m) => previous.pending.includes(m.id))
    : members).filter((m) => !m.paused);

  if (queue.length === 0) {
    await clearScanContinuation(env, ctx.chatId);
    await sendMessage(env, ctx.chatId,
      `✅ <b>${escapeHtml(group.name)}</b> — all ${members.length} domain${members.length === 1 ? "" : "s"} scanned.` +
      (paused.length > 0 ? `\n<i>${paused.length} paused domain${paused.length === 1 ? "" : "s"} skipped.</i>` : ""),
      { parseMode: "HTML" });
    return;
  }

  const batch = queue.slice(0, SCAN_GROUP_BATCH);
  const rest = queue.slice(SCAN_GROUP_BATCH);

  // Bounded concurrency: each member's CT/DNS providers are third-party HTTP
  // calls, so running the batch in parallel keeps the whole category inside
  // the webhook's wall-clock budget. runInitialScanInline never throws (it
  // reports failures into the chat), so one bad domain can't abort the batch.
  await Promise.all(batch.map((member) => runInitialScanInline(env, member.id, ctx.chatId)));

  if (rest.length > 0) {
    await saveScanContinuation(env, ctx.chatId, {
      groupId: group.id, groupName: group.name,
      pending: rest.map((m) => m.id), scanned: (previous?.scanned ?? 0) + batch.length,
      createdAt: new Date().toISOString(),
    });
    await sendMessage(env, ctx.chatId,
      `📂 <b>${escapeHtml(group.name)}</b>: scanned ${batch.length} of ${queue.length + (previous?.scanned ?? 0)} domains so far. ` +
      `<b>${rest.length}</b> left — send <code>/scan ${escapeHtml(group.name)}</code> again to continue. ` +
      `(They are also covered by the background schedule.)`,
      { parseMode: "HTML" });
  } else {
    await clearScanContinuation(env, ctx.chatId);
    const done = (previous?.scanned ?? 0) + batch.length;
    await sendMessage(env, ctx.chatId,
      `✅ <b>${escapeHtml(group.name)}</b> — ${done} domain${done === 1 ? "" : "s"} scanned.` +
      (paused.length > 0 ? `\n<i>${paused.length} paused domain${paused.length === 1 ? "" : "s"} skipped.</i>` : ""),
      { parseMode: "HTML" });
  }
}

export async function handleCommand(env: Env, ctx: CommandContext): Promise<void> {
  const { command, args } = parseCommand(ctx.text);
  const handler = handlers[command];
  if (!handler) {
    await sendMessage(env, ctx.chatId, `Unknown command /${command}. Send /help to see what I can do.`);
    return;
  }
  try {
    await handler(env, ctx, args);
  } catch (err) {
    await sendMessage(env, ctx.chatId, `❌ Command failed: ${String(err).slice(0, 300)}`);
  }
}

type CommandHandler = (env: Env, ctx: CommandContext, args: string[]) => Promise<void>;

/** Parse a /exclude value into a scope type: path → url, `*.x` → wildcard, else domain. */
export function classifyExclusion(raw: string): { type: ScopeType; value: string } | null {
  const v = raw.trim().toLowerCase();
  if (!v) return null;
  if (v.includes("/")) {
    // Path exclusion, e.g. example.com/admin or https://example.com/admin
    const withScheme = /^https?:\/\//.test(v) ? v : `https://${v}`;
    try {
      const u = new URL(withScheme);
      return { type: "url", value: `${u.origin}${u.pathname.replace(/\/$/, "")}` };
    } catch {
      return null;
    }
  }
  if (v.startsWith("*.")) {
    const d = normalizeDomain(v);
    return d ? { type: "wildcard_domain", value: `*.${d}` } : null;
  }
  const d = normalizeDomain(v);
  return d ? { type: "domain", value: d } : null;
}

const handlers: Record<string, CommandHandler> = {
  start: async (env, ctx) => {
    await sendMessage(env, ctx.chatId, messages.welcome(ctx.user?.first_name ?? "operator", ctx.user?.id ?? null), { parseMode: "HTML" });
  },

  help: async (env, ctx) => {
    await sendMessage(env, ctx.chatId, messages.help(), { parseMode: "HTML" });
  },

  target_add: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage: /target_add <category_name>\n" +
        "Example: /target_add shop\n" +
        "Then add domains to it: /add shop.example.com shop");
      return;
    }
    const name = args[0]!.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
      await sendMessage(env, ctx.chatId,
        "Category names may only contain letters, digits, dot, dash or underscore (max 64 chars).");
      return;
    }
    const existing = await getTargetGroupByNameOrId(env.DB, name);
    if (existing) {
      await sendMessage(env, ctx.chatId,
        `⚠️ Category <b>${escapeHtml(existing.name)}</b> already exists (${escapeHtml(existing.id)}).\n` +
        `Show it with <code>/target_info ${escapeHtml(existing.id)}</code>.`,
        { parseMode: "HTML" });
      return;
    }
    const group = await createTargetGroup(env.DB, name, ctx.user ? String(ctx.user.id) : null);
    await sendMessage(env, ctx.chatId,
      `📂 Category <b>${escapeHtml(group.name)}</b> created — id <code>${escapeHtml(group.id)}</code>\n\n` +
      `Add its domains:\n` +
      `<code>/add example.com ${escapeHtml(group.id)}</code>\n` +
      `<code>/add api.example.com ${escapeHtml(group.id)}</code>\n\n` +
      `Inspect it any time with <code>/target_info ${escapeHtml(group.id)}</code>`,
      { parseMode: "HTML" });
  },

  target_info: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage: /target_info <category_name_or_id>\n" +
        "Use /list to see all categories.");
      return;
    }
    const group = await getTargetGroupByNameOrId(env.DB, args[0]!);
    if (!group) {
      await sendMessage(env, ctx.chatId,
        `Category ${args[0]} not found. Create it with /target_add ${args[0]} or list them with /list.`);
      return;
    }

    const domains = await listTargetsByGroup(env.DB, group.id);
    const overview = await loadTargetOverview(env.DB, domains.map((d) => d.id));

    const lines = [
      `📂 <b>${escapeHtml(group.name)}</b> (${escapeHtml(group.id)})`,
      `Domains: <b>${domains.length}</b>`,
      "",
    ];

    if (domains.length === 0) {
      lines.push(`No domains yet — add one with <code>/add example.com ${escapeHtml(group.id)}</code>`);
    }

    for (const d of domains) {
      const last = overview.lastScan.get(d.id) ?? null;
      const excl = overview.exclusions.get(d.id) ?? 0;
      const map = overview.features.get(d.id)!;
      const onCount = countEnabled(map);
      lines.push(
        `• <code>${escapeHtml(d.name)}</code> — ${d.paused ? "⏸ paused" : "🟢 active"}`,
        `  id <code>${escapeHtml(d.id)}</code> · last scan: ${last ? relTime(last) : "never"}` +
        ` · exclusions: ${excl} · features: ${onCount}/${FEATURE_KEYS.length} on`,
        `  toggles: <code>/feature ${escapeHtml(d.name)}</code>`,
      );
    }

    lines.push(
      "",
      "<i>Feature toggles are per domain — use /feature &lt;domain&gt; on any member above.</i>",
    );
    await sendMessage(env, ctx.chatId, lines.join("\n"), { parseMode: "HTML" });
  },

  add: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage: /add <domain> [category]\n" +
        "Example: /add shop.example.com shop\n" +
        "Create the category first with /target_add shop (or omit it for a standalone domain).");
      return;
    }
    // Optional second arg = category (name or id) the domain belongs to.
    let group: { id: string; name: string } | null = null;
    if (args[1]) {
      const g = await getTargetGroupByNameOrId(env.DB, args[1]);
      if (!g) {
        await sendMessage(env, ctx.chatId,
          `Category ${escapeHtml(args[1])} not found. Create it first with /target_add ${escapeHtml(args[1])}, ` +
          `or omit the category to add a standalone domain.`,
          { parseMode: "HTML" });
        return;
      }
      group = g;
    }

    const domain = normalizeDomain(args[0]!);
    if (!domain) {
      await sendMessage(env, ctx.chatId, `❌ ${args[0]}: not a valid domain`);
      return;
    }

    const existing = await getTargetByNameOrId(env.DB, domain);
    if (existing) {
      // Re-adding into a category moves the existing domain into it.
      if (group && existing.group_id !== group.id) {
        await setTargetGroup(env.DB, existing.id, group.id);
        await sendMessage(env, ctx.chatId,
          `📂 Moved <code>${escapeHtml(domain)}</code> into category <b>${escapeHtml(group.name)}</b>.`,
          { parseMode: "HTML" });
        return;
      }
      await sendMessage(env, ctx.chatId, `⏭ ${escapeHtml(domain)}: already monitored. Try /scan ${escapeHtml(domain)}.`);
      return;
    }

    const target = await createTarget(
      env.DB, domain, ctx.user ? String(ctx.user.id) : null, group?.id ?? null,
    );
    const where = group ? ` in category <b>${escapeHtml(group.name)}</b>` : "";
    await sendMessage(env, ctx.chatId,
      `✅ Added <code>${escapeHtml(domain)}</code>${where} (id <code>${escapeHtml(target.id)}</code>).\n` +
      `Every subdomain is in scope.\n` +
      `Next: <code>/scan ${escapeHtml(domain)}</code>` +
      (group ? ` · <code>/target_info ${escapeHtml(group.id)}</code>` : ""),
      { parseMode: "HTML" });
  },

  remove: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage:\n" +
        "/remove <domain> — stop monitoring one domain\n" +
        "/remove <category> — stop a whole category (asks to confirm first)");
      return;
    }
    const ref = args[0]!;

    // ---- Confirmation step for a previously-offered category deletion ----
    if (args.length >= 2) {
      const token = args[1]!;
      const pending = await readRemoveConfirmation(env, ctx.chatId, token);
      if (!pending) {
        await sendMessage(env, ctx.chatId,
          "⚠️ That confirmation is invalid or expired (confirmations last 10 minutes).\n" +
          "Run <code>/remove &lt;category&gt;</code> again to get a fresh one.");
        return;
      }
      const deleted = await deleteGroupAndMembers(env, pending.groupId);
      await clearRemoveConfirmation(env, ctx.chatId);
      await sendMessage(env, ctx.chatId,
        `🗑 <b>Category ${escapeHtml(pending.groupName)}</b> and <b>${deleted}</b> ` +
        `domain${deleted === 1 ? "" : "s"} deleted. Monitoring and all stored ` +
        `findings for ${deleted === 1 ? "it" : "them"} were removed.`,
        { parseMode: "HTML" });
      return;
    }

    // ---- A category name/id: confirm before destroying its domains ------
    const group = await getTargetGroupByNameOrId(env.DB, ref);
    if (group) {
      const members = await listTargetsByGroup(env.DB, group.id);
      if (members.length === 0) {
        // Nothing to destroy — just drop the empty category.
        await deleteTargetGroup(env.DB, group.id);
        await sendMessage(env, ctx.chatId,
          `🗑 Empty category <b>${escapeHtml(group.name)}</b> removed.`, { parseMode: "HTML" });
        return;
      }
      const token = await saveRemoveConfirmation(env, ctx.chatId, {
        groupId: group.id, groupName: group.name,
        domainCount: members.length, createdAt: new Date().toISOString(),
      });
      const memberList = members.slice(0, 10).map((m) => `• <code>${escapeHtml(m.name)}</code>`).join("\n");
      const more = members.length > 10 ? `\n<i>…and ${members.length - 10} more</i>` : "";
      await sendMessage(env, ctx.chatId,
        `⚠️ <b>Remove category ${escapeHtml(group.name)}?</b>\n\n` +
        `This deletes the category AND all <b>${members.length}</b> domain${members.length === 1 ? "" : "s"} ` +
        `under it, together with every stored asset, scan and finding:\n` +
        `${memberList}${more}\n\n` +
        `To confirm, send:\n<code>/remove ${escapeHtml(group.name)} ${escapeHtml(token)}</code>\n\n` +
        `<i>Or /remove ${escapeHtml(members[0]!.name)} to delete just one domain and keep the category.</i>`,
        { parseMode: "HTML" });
      return;
    }

    // ---- A plain domain ----
    const target = await getTargetByNameOrId(env.DB, ref);
    if (!target) {
      await sendMessage(env, ctx.chatId,
        `Neither a category nor a domain named <code>${escapeHtml(ref)}</code> was found.`);
      return;
    }
    await deleteTarget(env.DB, target.id);
    await sendMessage(env, ctx.chatId, `🗑 ${target.name} removed. Monitoring and all its stored findings were deleted.`);
  },

  list: async (env, ctx) => {
    const groups = await listTargetGroups(env.DB);
    const targets = await listTargets(env.DB);
    if (targets.length === 0 && groups.length === 0) {
      await sendMessage(env, ctx.chatId,
        "No targets yet. Add one with /add example.com\n" +
        "Or create a category first: /target_add shop\n" +
        "Then add its domains: /add shop.example.com shop");
      return;
    }
    const lines: string[] = [];

    // Categories first, each with its member domains indented underneath.
    for (const g of groups) {
      const members = targets.filter((t) => t.group_id === g.id);
      lines.push(
        `📂 <b>${escapeHtml(g.name)}</b> (<code>${escapeHtml(g.id)}</code>) — ` +
        `${members.length} domain${members.length === 1 ? "" : "s"}`,
      );
      for (const m of members) {
        lines.push(
          `  ${m.paused ? "⏸" : "🟢"} <code>${escapeHtml(m.name)}</code>` +
          ` — <code>/feature ${escapeHtml(m.name)}</code>`,
        );
      }
      lines.push(`  <i>details: /target_info ${escapeHtml(g.id)}</i>`, "");
    }

    const standalone = targets.filter((t) => !t.group_id);
    if (standalone.length > 0) {
      lines.push(`<b>Standalone domains</b>`);
      for (const t of standalone) lines.push(`• ${t.paused ? "⏸" : "🟢"} <code>${escapeHtml(t.name)}</code>`);
      lines.push("");
    }

    for (const t of targets) {
      const counts = await env.DB
        .prepare(
          `SELECT
             (SELECT COUNT(*) FROM assets WHERE target_id = ?1 AND asset_type = 'subdomain' AND scope_state = 'allowed') AS subs,
             (SELECT COUNT(*) FROM services WHERE target_id = ?1) AS live,
             (SELECT COUNT(*) FROM findings WHERE target_id = ?1 AND status = 'open') AS findings,
             (SELECT MAX(created_at) FROM scans WHERE target_id = ?1 AND status = 'completed') AS last_scan`,
        )
        .bind(t.id)
        .first<{ subs: number; live: number; findings: number; last_scan: string | null }>();
      const status = t.paused ? "⏸" : "🟢";
      lines.push(
        `${status} <b>${t.name}</b>\n` +
        `    Subdomains: ${counts?.subs ?? 0} · Live hosts: ${counts?.live ?? 0} · Open findings: ${counts?.findings ?? 0}\n` +
        `    Last scan: ${counts?.last_scan ? counts.last_scan.replace("T", " ").slice(0, 16) + "Z" : "never"}`,
      );
      const exclusions = (await listScopeEntries(env.DB, t.id)).filter((e) => !e.included);
      if (exclusions.length > 0) {
        lines.push(`    🚫 Excluded: ${exclusions.map((e) => e.value).join(", ")}`);
      }
    }
    await sendMessage(env, ctx.chatId, `📋 <b>Targets</b>\n\n${lines.join("\n\n")}`, { parseMode: "HTML" });
  },

  exclude: async (env, ctx, args) => {
    // /exclude list <domain>
    if (args[0]?.toLowerCase() === "list") {
      const target = await getTargetByNameOrId(env.DB, args[1] ?? "");
      if (!target) { await sendMessage(env, ctx.chatId, "Usage: /exclude list <domain>"); return; }
      const exclusions = (await listScopeEntries(env.DB, target.id)).filter((e) => !e.included);
      await sendMessage(env, ctx.chatId, exclusions.length
        ? `🚫 Exclusions for ${target.name}:\n${exclusions.map((e) => `• [${e.type}] ${e.value}`).join("\n")}`
        : `No exclusions for ${target.name}.`);
      return;
    }

    // /exclude remove <domain> <value>
    if (args[0]?.toLowerCase() === "remove") {
      const target = await getTargetByNameOrId(env.DB, args[1] ?? "");
      if (!target || !args[2]) { await sendMessage(env, ctx.chatId, "Usage: /exclude remove <domain> <value>"); return; }
      const removed = await removeScopeEntry(env.DB, target.id, args[2]!.toLowerCase());
      await sendMessage(env, ctx.chatId, removed
        ? `✅ ${args[2]} is no longer excluded from ${target.name}.`
        : `No active exclusion "${args[2]}" on ${target.name}.`);
      return;
    }

    // /exclude <domain> <value...>
    if (args.length < 2) {
      await sendMessage(env, ctx.chatId,
        "Usage: /exclude <domain> <value>\n" +
        "Examples:\n" +
        "/exclude example.com sub.example.com\n" +
        "/exclude example.com *.dev.example.com\n" +
        "/exclude example.com example.com/excluded\n\n" +
        "/exclude list <domain> · /exclude remove <domain> <value>");
      return;
    }
    const target = await getTargetByNameOrId(env.DB, args[0]!);
    if (!target) { await sendMessage(env, ctx.chatId, `Target ${args[0]} not found. Add it first with /add.`); return; }

    const lines: string[] = [];
    for (const raw of args.slice(1)) {
      const parsed = classifyExclusion(raw);
      if (!parsed) { lines.push(`❌ ${raw}: could not parse`); continue; }
      if (parsed.value === target.name && parsed.type === "domain") {
        lines.push(`❌ ${raw}: that's the target itself`);
        continue;
      }
      try {
        await insertScopeEntry(env.DB, target.id, parsed.type, parsed.value, true, ctx.user ? String(ctx.user.id) : null);
        lines.push(`🚫 Excluded ${parsed.value}`);
      } catch {
        lines.push(`⏭ ${parsed.value}: already excluded`);
      }
    }
    lines.push(`Exclusions apply immediately — scanning of these assets stops.`);
    await sendMessage(env, ctx.chatId, lines.join("\n"));
  },

  scan: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage: /scan <category_or_domain>\n" +
        "Scanning a category scans every domain filed under it.\n" +
        "Example: /scan shop");
      return;
    }
    // A category name or id scans every member domain; a domain name or id
    // scans just that one. Categories are checked first — their names live in
    // their own namespace, and every member must be covered.
    const group = await getTargetGroupByNameOrId(env.DB, args[0]!);
    if (group) {
      await scanGroup(env, ctx, group);
      return;
    }
    const target = await getTargetByNameOrId(env.DB, args[0]!);
    if (!target) {
      await sendMessage(env, ctx.chatId, `Target ${args[0]} not found. Add it first with /add ${args[0]}.`);
      return;
    }
    if (target.paused) { await sendMessage(env, ctx.chatId, `⏸ ${target.name} is paused.`); return; }
    await runInitialScanInline(env, target.id, ctx.chatId);
  },

  feature: async (env, ctx, args) => {
    if (args.length < 1) {
      await sendMessage(env, ctx.chatId,
        "Usage:\n" +
        "/feature <domain> — list this domain's monitoring features\n" +
        "/feature <domain> <key> <on|off> — toggle one (features are per domain)\n" +
        "Example: /feature example.com port_watch off");
      return;
    }
    const target = await getTargetByNameOrId(env.DB, args[0]!);
    if (!target) {
      const group = await getTargetGroupByNameOrId(env.DB, args[0]!);
      if (group) {
        // Features are per DOMAIN — point at the members instead of guessing.
        const members = await listTargetsByGroup(env.DB, group.id);
        const memberLines = members.map((m) => `• <code>/feature ${escapeHtml(m.name)}</code>`);
        await sendMessage(env, ctx.chatId,
          `⚙️ Features are configured per domain, not per category. Members of ` +
          `<b>${escapeHtml(group.name)}</b>:\n` +
          (memberLines.length > 0 ? memberLines.join("\n") : "(no domains in this category yet)"),
          { parseMode: "HTML" });
        return;
      }
      await sendMessage(env, ctx.chatId, `Target ${args[0]} not found. Add it first with /add ${args[0]}.`);
      return;
    }

    const actor = ctx.user ? String(ctx.user.id) : null;

    // /feature <target> → status board.
    if (args.length === 1) {
      const map = await getFeatureMap(env.DB, target.id);
      const lines = [`⚙️ <b>Monitoring features for ${escapeHtml(target.name)} (${target.id})</b>`, ""];
      for (const key of FEATURE_KEYS) {
        const meta = FEATURES[key]!;
        const on = map[key];
        lines.push(
          `• ${escapeHtml(meta.label)} — ${on ? "🟢 ON" : "🔴 OFF"}\n` +
          `  ${escapeHtml(meta.blurb)} · key: <code>${key}</code>`,
        );
      }
      lines.push(
        "",
        "Toggle one: <code>/feature " + escapeHtml(target.id) + " &lt;key&gt; &lt;on|off&gt;</code>",
        `Example: <code>/feature ${escapeHtml(target.id)} port_watch off</code>`,
      );
      await sendMessage(env, ctx.chatId, lines.join("\n"), { parseMode: "HTML" });
      return;
    }

    if (args.length < 3) {
      await sendMessage(env, ctx.chatId,
        "Usage: /feature <target> <key> <on|off>\n" +
        `Keys: ${FEATURE_KEYS.join(" · ")}`);
      return;
    }

    const key = args[1]!.toLowerCase().replace(/-/g, "_") as FeatureKey;
    if (!(FEATURE_KEYS as string[]).includes(key)) {
      await sendMessage(env, ctx.chatId, `Unknown feature "${args[1]}".\nKeys: ${FEATURE_KEYS.join(" · ")}`);
      return;
    }

    const raw = args[2]!.toLowerCase();
    if (raw !== "on" && raw !== "off") {
      await sendMessage(env, ctx.chatId, "State must be on or off.\nExample: /feature example.com port_watch off");
      return;
    }
    if (key === "nuclei" && raw === "on") {
      await sendMessage(env, ctx.chatId,
        `⚠️ <b>${escapeHtml(FEATURES.nuclei.label)}</b> needs an external runner, ` +
        `which this bot doesn't have — it stays 🔴 OFF. ` +
        `Turning it on here changes nothing until a runner exists.`,
        { parseMode: "HTML" });
      return;
    }

    await setFeature(env.DB, target.id, key, raw === "on", actor);
    const emoji = raw === "on" ? "🟢" : "🔴";
    await sendMessage(env, ctx.chatId,
      `${emoji} <b>${escapeHtml(FEATURES[key]!.label)}</b> is now <b>${raw.toUpperCase()}</b> for ${escapeHtml(target.name)}.` +
      (raw === "off" ? "\nThat phase is skipped entirely from the next scan pass." : ""),
      { parseMode: "HTML" });
  },

  allow: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /allow <telegram_id>"); return; }
    const id = args[0]!.replace(/\D/g, "");
    if (!id) { await sendMessage(env, ctx.chatId, "That doesn't look like a Telegram ID (numeric)."); return; }
    await addAllowedUser(env.DB, id, ctx.user ? String(ctx.user.id) : null);
    await sendMessage(env, ctx.chatId, `✅ User ${id} can now use this bot.`);
  },

  disallow: async (env, ctx, args) => {
    if (args.length < 1) { await sendMessage(env, ctx.chatId, "Usage: /disallow <telegram_id>"); return; }
    const id = args[0]!.replace(/\D/g, "");
    if ((env.AUTHORIZED_TELEGRAM_IDS ?? "").split(",").map((s) => s.trim()).includes(id)) {
      await sendMessage(env, ctx.chatId, `⚠️ ${id} is in the AUTHORIZED_TELEGRAM_IDS env var — remove it there to revoke access (it is re-seeded on every boot).`);
      return;
    }
    const removed = await removeAllowedUser(env.DB, id);
    await sendMessage(env, ctx.chatId, removed ? `🚫 User ${id} revoked.` : `User ${id} was not in the runtime allowlist.`);
  },
};
