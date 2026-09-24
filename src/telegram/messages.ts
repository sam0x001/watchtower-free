// src/telegram/messages.ts
// User-facing Telegram message templates. Never include full secrets/tokens/cookies.

export const messages = {
  welcome: (firstName: string, telegramId: number | null) =>
    `🛡️ <b>Watchtower, ${firstName}!</b>\n\n` +
    `Continuous monitoring for bug bounty targets: subdomain enumeration (CT logs + wordlist bruteforce), ` +
    `asset &amp; JS discovery, sensitive-data fuzzing, technology fingerprinting and CVE matching. ` +
    `Every new finding lands in this chat.\n\n` +
    (telegramId ? `Your Telegram ID: <code>${telegramId}</code>\n` : "") +
    `<b>Quick start</b>\n` +
    `<code>/target-add shop</code>\n` +
    `<code>/add shop.example.com shop</code>\n` +
    `<code>/target-info shop</code>\n` +
    `<code>/scan shop.example.com</code>\n` +
    `<code>/feature shop.example.com</code>`,

  help: () =>
    `<b>Watchtower Commands</b>\n\n` +
    `<b>Targets</b>\n` +
    `/target-add &lt;name&gt; — create a target category (e.g. /target-add shop)\n` +
    `/target-info &lt;name|id&gt; — list every domain added under that category\n` +
    `/add &lt;domain&gt; [category] — start monitoring (wildcards implied: every subdomain is in scope)\n` +
    `/remove &lt;domain&gt; — stop monitoring\n` +
    `/list — categories, domains, exclusions, asset counts\n\n` +
    `<b>Exclusions</b>\n` +
    `/exclude &lt;domain&gt; &lt;value&gt; — skip a subdomain (\u200bsub.example.com\u200b), wildcard (\u200b*.dev.example.com\u200b) or path (\u200bexample.com/admin\u200b)\n` +
    `/exclude list &lt;domain&gt;\n` +
    `/exclude remove &lt;domain&gt; &lt;value&gt;\n\n` +
    `<b>Scanning</b>\n` +
    `/scan &lt;domain&gt; — initial scan now (results in chat), then continuous monitoring\n` +
    `/feature &lt;domain&gt; — status board of that domain's monitoring features\n` +
    `/feature &lt;domain&gt; &lt;key&gt; &lt;on|off&gt; — toggle one feature (per domain)\n\n` +
    `<b>Access</b>\n` +
    `/allow &lt;telegram_id&gt; — let another user talk to this bot\n` +
    `/disallow &lt;telegram_id&gt; — revoke access`,
};
