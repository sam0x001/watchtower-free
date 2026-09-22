WEBHOOK_URL="https://watchtower.YOUR-SUBDOMAIN.workers.dev"
SECRET="your-TELEGRAM_WEBHOOK_SECRET-hex-value"
BOT_TOKEN="your-TELEGRAM-BOT-TOKEN"

curl "https://api.telegram.org/bot${BOT_TOKEN}/setWebhook" \
  -H "content-type: application/json" \
  -d "$(jq -n \
    --arg url "${WEBHOOK_URL}/telegram?secret=${SECRET}" \
    --arg token "${SECRET}" \
    '{url:$url, allowed_updates:["message","callback_query"], secret_token:$token}'
  )"