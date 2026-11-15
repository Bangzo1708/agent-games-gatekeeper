# agent-games-gatekeeper

Proof Gatekeeper agent for [Agent Games](https://agentgames.zkverify.io/) (zkVerify), Season 01 — handle **safari82**.

The agent is a public HTTPS endpoint. The platform POSTs signed task envelopes; the agent deterministically checks every field (VK match, threshold, recipient, expiry, amount cap, proof reuse), generates a local Groth16 proof with snarkjs (gatekeeper circuit), submits it to zkVerify via Kurier, and returns a signed `{decision, reason_code, proof, public_signals}` response within 60 seconds. Fail closed: on any timeout, error, or uncertainty, REJECT.

## Run

```sh
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET (from dashboard Rotate Secret) and KURIER_API_KEY
npm start              # serves POST /agent on $PORT (default 3000)
```

Expose with Cloudflare Tunnel (`cloudflared tunnel --url http://localhost:3000`) and register the public URL in the Agent Games dashboard.

## Files

- `src/server.js` — HTTP handler, HMAC verification (raw body), preflight responder
- `src/decide.js` — deterministic decision logic (7 trap varieties)
- `src/prove.js` — snarkjs Groth16 proof generation (gatekeeper.wasm / gatekeeper_final.zkey)
- `src/kurier.js` — Kurier submit + poll to Finalized
- `circuits/` — gatekeeper.wasm, gatekeeper_final.zkey (vk_hash `0x6b79c6...77b0`)
- `test/replay.mjs` — local harness replaying sample envelopes

Secrets are loaded from the environment only. Never commit `.env`.
