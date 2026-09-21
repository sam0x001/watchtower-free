// src/telegram/messages.ts
// User-facing Telegram message templates. Never include full secrets/tokens/cookies.

export const messages = {
  welcome: (firstName: string) =>
    `🛡️ <b>Welcome to Watchtower, ${firstName}!</b>\n\n` +
    `Watchtower continuously monitors your authorized security targets for new assets, subdomains, DNS changes, exposed services, JavaScript changes, API endpoints, technologies, CVEs, and vulnerabilities.\n\n` +
    `<b>Principles enforced</b>\n` +
    `• Explicit authorization required before any target is added\n` +
    `• Passive reconnaissance by default\n` +
    `• Human in the loop for any intrusive check\n` +
    `• Never out-of-scope scanning\n` +
    `• Never automatic exploitation\n` +
    `• Complete audit trail of every action\n\n` +
    `Type /help to see all commands.\n\n` +
    `<b>Quick start</b>\n` +
    `<code>/authorize example.com WRITTEN-CONTRACT-2026-001</code>\n` +
    `<code>/scope_add TGT_xxx domain example.com</code>\n` +
    `<code>/scan_passive TGT_xxx</code>`,

  help: () =>
    `<b>Watchtower Commands</b>\n\n` +
    `<b>Authorization</b>\n` +
    `/authorize &lt;target&gt; &lt;reference&gt;\n\n` +
    `<b>Scope</b>\n` +
    `/scope_add &lt;target_id&gt; &lt;type&gt; &lt;value&gt; [--exclude]\n` +
    `/scope_list &lt;target_id&gt;\n` +
    `/scope_update &lt;scope_id&gt; &lt;new_value&gt;\n` +
    `/scope_remove &lt;scope_id&gt;\n` +
    `/scope_pause &lt;scope_id&gt;\n` +
    `/scope_resume &lt;scope_id&gt;\n` +
    `/scope_expire &lt;scope_id&gt;\n\n` +
    `<b>Targets</b>\n` +
    `/target_add &lt;org_id&gt; &lt;name&gt; &lt;expires YYYY-MM-DD&gt;\n` +
    `/target_list &lt;org_id&gt;\n` +
    `/target_details &lt;target_id&gt;\n` +
    `/target_pause &lt;target_id&gt;\n` +
    `/target_resume &lt;target_id&gt;\n\n` +
    `<b>Scans</b>\n` +
    `/scan_passive &lt;target_id&gt;\n` +
    `/scan_active &lt;target_id&gt; confirm\n` +
    `/scan_status &lt;scan_id&gt;\n` +
    `/scan_cancel &lt;scan_id&gt;\n` +
    `/scan_history &lt;target_id&gt;\n\n` +
    `<b>Findings</b>\n` +
    `/findings_list &lt;org_id&gt; [status] [severity]\n` +
    `/finding_details &lt;finding_id&gt;\n` +
    `/finding_verify &lt;finding_id&gt;\n` +
    `/finding_reject &lt;finding_id&gt;\n` +
    `/finding_assign &lt;finding_id&gt; &lt;user_id&gt;\n` +
    `/finding_close &lt;finding_id&gt;\n` +
    `/finding_reopen &lt;finding_id&gt;\n\n` +
    `<b>Reports</b>\n` +
    `/report_create &lt;target_id&gt; &lt;format&gt;\n` +
    `/report_export &lt;report_id&gt;\n\n` +
    `<b>Diffs</b>\n` +
    `/diff_latest &lt;target_id&gt;\n` +
    `/diff_compare &lt;target_id&gt; &lt;older&gt; &lt;newer&gt;\n\n` +
    `<b>Alerts &amp; schedules</b>\n` +
    `/alerts_enable &lt;target_id&gt;\n` +
    `/alerts_disable &lt;target_id&gt;\n` +
    `/schedule_add &lt;target_id&gt; &lt;cron&gt; &lt;profile&gt;\n` +
    `/schedule_list &lt;target_id&gt;\n` +
    `/schedule_remove &lt;schedule_id&gt;\n\n` +
    `<b>Integrations &amp; team</b>\n` +
    `/integration_add &lt;org_id&gt; &lt;type&gt; [config_json]\n` +
    `/integration_remove &lt;integration_id&gt;\n` +
    `/team_invite &lt;org_id&gt; &lt;telegram_id&gt; [role]\n` +
    `/team_members &lt;org_id&gt;\n\n` +
    `<b>Operations</b>\n` +
    `/settings\n` +
    `/audit &lt;org_id&gt; [action]\n` +
    `/stop [global|organization|target|job] [id] [reason...]\n` +
    `/resume [global|organization|target|job] [id]`,

  emergencyStop: () =>
    `🛑 <b>EMERGENCY STOP ACTIVATED</b>\n\n` +
    `All scheduled jobs have been cancelled. New scans are blocked until /resume is issued.\n` +
    `Active external runners will be told to abort their current job at the next heartbeat.`,
};
