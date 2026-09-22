# Watchtower — Incident Response Procedure

## When to invoke

Invoke this procedure when any of the following occur:

1. An unauthorized target was added or scanned.
2. A scan went out of scope (e.g., a redirect leaked to a third party).
3. An emergency-stop was triggered by an automated check.
4. A suspected secret was found in logs or notifications.
5. A scanner runner appears compromised.
6. A breach of the encrypted evidence store is suspected.

## Severity classification

| Level | Definition | Examples |
|-------|------------|----------|
| SEV-0 | Critical — active unauthorized scanning | Operator scanned third-party infrastructure without authorization |
| SEV-1 | High — secrets leaked in logs/notifications | Telegram message contained a full API key |
| SEV-2 | Medium — out-of-scope asset briefly probed | A redirect from in-scope asset to third party was followed |
| SEV-3 | Low — evidence of policy violation | Scope was added without recorded authorization |

## Response steps

### Step 1 — Stop the bleeding (≤ 5 minutes)

1. Issue `/stop global` via Telegram to cancel all running scans.
2. Verify the emergency stop is active via `GET https://watchtower.example.workers.dev/v1/health`.
3. Pause every target: `UPDATE targets SET paused = 1`.
4. Revoke any suspect API tokens via the database.
5. If a runner is suspected compromised, revoke it:
   `UPDATE runners SET revoked = 1, revoked_reason = 'incident-<id>' WHERE id = ?`.

### Step 2 — Contain (≤ 30 minutes)

1. Identify the scope of impact:
   - Which targets were affected?
   - Which findings were generated?
   - Which notifications were sent?
2. Pull the audit log for the affected time window:
   `SELECT * FROM audit_logs WHERE created_at > ? ORDER BY created_at DESC LIMIT 1000`.
3. Snapshot the D1 database: `wrangler d1 export watchtower-db --remote > snapshot.sql`.
4. Snapshot R2 evidence: list objects under `evidence/` for the affected orgs.

### Step 3 — Eradicate (≤ 4 hours)

1. Delete any unauthorized scope entries.
2. Revoke the compromised operator's access.
3. Rotate `ENCRYPTION_KEY`, `API_HMAC_KEY`, `WEBHOOK_SIGNING_SECRET`,
   `RUNNER_REGISTRY_TOKEN`, and any leaked third-party credentials.
4. Re-encrypt affected evidence with the new `ENCRYPTION_KEY` (requires a
   one-off rotation script — see `scripts/rotate-encryption-key.ts`).

### Step 4 — Recover (≤ 24 hours)

1. Re-add authorized targets and scope.
2. Resume monitoring via `/resume`.
3. Run a baseline passive scan to verify the platform is functional.
4. Notify affected program owners / clients if their scope was impacted.

### Step 5 — Postmortem (≤ 7 days)

1. Document the timeline, root cause, and lessons learned.
2. Update the threat model (`docs/threat-model.md`).
3. Add new test cases to prevent regression.
4. File improvement tickets for any control gaps.

## Communication templates

### Initial notification (internal)

> Incident ID: INC-YYYYMMDD-NNN
> Detected at: <ISO timestamp>
> Severity: SEV-N
> Summary: <one-paragraph description>
> Containment status: <in progress / contained / resolved>
> Owner: <on-call engineer>

### External notification (to affected program owner)

> Watchtower security incident notification
>
> We detected unauthorized activity affecting your authorized scope on
> <date>. As a precaution we have paused all monitoring of your targets
> and are conducting a full investigation. We will share a detailed
> postmortem within 7 business days.
>
> If you have questions, contact <security-contact@your-org>.
