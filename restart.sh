#!/usr/bin/env bash
# Restart everything after a VM restart (or a crash):
#   1. agent server (./start.sh, needs .env with AGENT_GAMES_HMAC_SECRET)
#   2. ngrok tunnel (./tunnel-ngrok.sh, needs .env with NGROK_AUTHTOKEN)
# The ngrok URL changes on every restart -> the printed URL MUST be updated
# in the Agent Games dashboard (My Agents -> Edit agent) before preflight
# will reach the new endpoint.
# Then verify: local /healthz + a POST through the public URL.
set -euo pipefail
cd "$(dirname "$0")"

SERVER_PID="$(pgrep -f "node src/server.mjs" || true)"
if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; sleep 1; fi
nohup ./start.sh > /tmp/agent-server.log 2>&1 &
sleep 3
echo "--- server ---"
curl -sS --max-time 10 http://localhost:${PORT:-3000}/healthz || { echo "server did not come up; see /tmp/agent-server.log" >&2; exit 1; }
echo
./tunnel-ngrok.sh
echo "--- public check (unsigned POST -> expect 401) ---"
CHANNEL="$(cat tunnel-url.txt)"
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST "$CHANNEL" -H 'content-type: application/json' -d '{"ping":1}')"
echo "public POST http=$CODE (401 = reachable, HMAC working; anything else = investigate)"
echo "DONE. Endpoint: $CHANNEL — update it in the dashboard if it changed."
