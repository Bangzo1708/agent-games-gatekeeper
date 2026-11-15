#!/usr/bin/env bash
# Start the Proof Gatekeeper agent server.
# Loads .env (mode 600, never committed) then runs node src/server.mjs.
# Usage: ./start.sh  (from the repo root)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi
if [ -z "${AGENT_GAMES_HMAC_SECRET:-}" ]; then
  echo "AGENT_GAMES_HMAC_SECRET is not set (fill .env first)" >&2
  exit 1
fi
exec node src/server.mjs
