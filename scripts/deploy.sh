#!/usr/bin/env bash
# scripts/deploy.sh — end-to-end Watchtower deployment helper.
# Usage: ./scripts/deploy.sh [staging|production]

set -euo pipefail

ENV="${1:-production}"
WRANGLER="npx wrangler"

echo "==> Deploying Watchtower to ${ENV}"

# 1. Verify required secrets are set
echo "==> Verifying required secrets..."
REQUIRED_SECRETS=(
  TELEGRAM_BOT_TOKEN
  TELEGRAM_WEBHOOK_SECRET
  AUTHORIZED_TELEGRAM_IDS
  ENCRYPTION_KEY
  API_HMAC_KEY
  WEBHOOK_SIGNING_SECRET
  RUNNER_REGISTRY_TOKEN
)

if [[ "$ENV" == "production" ]]; then
  for secret in "${REQUIRED_SECRETS[@]}"; do
    if ! $WRANGLER secret list 2>&1 | grep -q "^$secret\b"; then
      echo "!! Missing secret: $secret"
      echo "!! Run: wrangler secret put $secret"
      exit 1
    fi
  done
fi

# 2. Deploy the Worker
echo "==> Deploying Worker..."
if [[ "$ENV" == "production" ]]; then
  $WRANGLER deploy
else
  $WRANGLER deploy --env "$ENV"
fi

# 3. Apply DB migrations
# Deliberately AFTER the deploy: a migration that removes or renames columns
# (e.g. migrations/0012_audit_logs_reconcile.sql, which drops the leftover
# audit_logs columns) must not run while the previous Worker version — which
# still writes those columns — is serving traffic.
echo "==> Applying D1 migrations..."
if [[ "$ENV" == "production" ]]; then
  $WRANGLER d1 migrations apply watchtower-db --remote
else
  $WRANGLER d1 migrations apply watchtower-db --local
fi

echo "==> Done."
echo
echo "Next steps:"
echo "  1. Register the Telegram webhook (see DEPLOYMENT.md)."
echo "  2. Bootstrap the organization + owner user in D1."
echo "  3. Add your first target via /target_add."
