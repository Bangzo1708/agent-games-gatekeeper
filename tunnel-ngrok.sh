#!/usr/bin/env bash
# Expose the local agent (localhost:$PORT, default 3000) on a public HTTPS URL
# via ngrok (binary in ./bin/ngrok, v3.39.13; works through the egress proxy).
#
# Requires a real ngrok authtoken in .env (NGROK_AUTHTOKEN) — get one free at
# https://dashboard.ngrok.com/get-started/your-authtoken (no card needed).
# The public URL is random per start on the free tier (https://<id>.ngrok-free.app)
# and is printed at the end + saved to tunnel-url.txt.
#   Register that exact URL in the Agent Games dashboard (My Agents -> Edit agent).
#   On restart the URL changes -> run this again and update the dashboard.
# Usage: ./tunnel-ngrok.sh
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-3000}"
URL_FILE="tunnel-url.txt"
LOG="tunnel-ngrok.log"

if [ -f .env ]; then set -a; source .env; set +a; fi
if [ -z "${NGROK_AUTHTOKEN:-}" ]; then
  echo "NGROK_AUTHTOKEN is not set — add it to .env (free token: https://dashboard.ngrok.com/get-started/your-authtoken)" >&2
  exit 1
fi

# Kill any previous ngrok for this port (restart-safe).
NGROK_PID="$(pgrep -f "ngrok http ${PORT}" || true)"
if [ -n "$NGROK_PID" ]; then kill "$NGROK_PID" 2>/dev/null || true; sleep 2; fi

nohup ./bin/ngrok http "$PORT" --authtoken "$NGROK_AUTHTOKEN" --log stdout --log-level info > "$LOG" 2>&1 &
echo "ngrok pid $! -> $LOG"

# Wait for the tunnel URL (ngrok prints "started tunnel" with the public URL).
for _ in $(seq 1 30); do
  sleep 2
  if grep -q "ERR_NGROK" "$LOG"; then
    echo "ngrok failed:" >&2; grep "ERR_NGROK" "$LOG" | head -3 >&2; exit 1
  fi
  URL="$(grep -oE 'https://[a-zA-Z0-9-]+\.ngrok(-free)?\.app' "$LOG" | head -1 || true)"
  if [ -n "$URL" ]; then
    echo "$URL" > "$URL_FILE"
    echo "PUBLIC ENDPOINT: $URL"
    echo "Register this exact URL in the Agent Games dashboard (My Agents -> Edit agent)."
    exit 0
  fi
done
echo "ngrok did not report a URL in 60s; see $LOG" >&2
exit 1
