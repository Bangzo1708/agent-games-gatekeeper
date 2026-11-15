# agent-games-gatekeeper

Proof Gatekeeper agent for [Agent Games](https://agentgames.zkverify.io/) (zkVerify),
Season 01 — handle **safari82**.

The agent is a public HTTPS endpoint. The platform POSTs signed task envelopes;
the agent deterministically checks every field (VK match, threshold, recipient,
expiry, amount cap, proof reuse), generates a local Groth16 proof with snarkjs
(gatekeeper circuit), submits it to zkVerify via Kurier, and returns a signed
`{decision, reason_code, proof, public_signals}` response within 60 seconds.
Fail closed: on any timeout, error, or uncertainty, REJECT.

## Circuit mapping (reverse-engineered 15 Nov 2026)

Full notes: `../circuit-probe/MAPPING.md`. Essentials:

- Field is the BN128 **scalar field r** (not the base field p); snarkjs reduces
  inputs mod r. Feed full decimal strings for 256-bit hashes.
- Public signals (13, snarkjs order): `[0]=Poseidon([salt,taskId])`,
  `[1]=registeredVk mod r`, `[2]=proofVk mod r`, `[3]=minimum`,
  `[4]=publicBalance`, `[5]=expiryBlock`, `[6]=currentBlock`, `[7]=recipient`,
  `[8]=conditionRecipient`, `[9]=amount`, `[10]=maxTransfer`,
  `[11]=decision (1 APPROVE / 0 REJECT)`, `[12]=taskId`.
- APPROVE iff vk match AND balance ≥ minimum AND `currentBlock < expiryBlock`
  (**STRICT** — the expiry block itself is expired) AND recipient match AND
  amount ≤ maxTransfer AND proof_tx not seen before.
- Provability guard: each compared pair must differ by < 2³², else the circuit
  can prove NEITHER decision — answer the correct decision with NO proof.
- PROOF_REUSED is a platform rule: respond REJECT with NO proof (the circuit
  refuses a false REJECT — witness assert, GatekeeperEvaluation_79 line 102).
- `task_id` → field element: `keccak256(utf8(task_id)) mod r` (best candidate;
  the platform publishes no mapping — confirmed or corrected by the first
  practice task; override with `TASK_ID_ENCODING`).
- Salt: fresh random 128-bit per task, never reused, never logged.

## Run

```sh
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET + NGROK_AUTHTOKEN (+ KURIER_API_KEY)
npm test               # local harness: 13 decision cases + 2 end-to-end proofs
./start.sh             # serves POST /agent on $PORT (default 3000)
./tunnel-ngrok.sh      # public https://<id>.ngrok-free.app -> localhost:3000
```

## Tunnel

ngrok v3 (binary in `bin/`, not committed — download if missing):

```sh
curl -sSL -o /tmp/ngrok-v3.zip https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip
unzip -o /tmp/ngrok-v3.zip -d bin/
```

Free authtoken: https://dashboard.ngrok.com/get-started/your-authtoken
(no card). The URL is random per start on the free tier — after every
restart, update the endpoint in the Agent Games dashboard
(My Agents → Edit agent), then re-run preflight.

Dead ends tried 15 Nov 2026: Cloudflare trycloudflare (Cloudflare 403s this
egress IP), pinggy/localhost.run/serveo (SSH blocked by the egress proxy),
localtunnel (hangs, no URL), smee.io (one-way relay — the platform never
receives our response). ngrok is the only working tunnel.

## Dashboard setup (once, then on every URL change)

Prerequisite: Settings → Connected accounts → GitHub must say **connected**
(`githubLinked: true`, handle shown). Beware: the "Identity verified / GitHub
account linked" line is identity verification, NOT the account link — the
account row must not say "Not connected", or registration is refused. Link it
via https://agentgames.zkverify.io/api/auth/github (browser, authorize as
Bangzo1708).

1. Register the agent (endpoint optional at this step):
   `python3 ../register-agent.py` (from `~/workspace/agentgames/`) — captures
   the agentId + one-time secret into `.env`.
2. Start ngrok (`./tunnel-ngrok.sh`), then set the endpoint:
   `python3 ../ag-action.py 60ee2f3447b3d5ed963486eb975750c24725a4f3b6 updateAgentEndpoint '["<agentId>", "<ngrok-url>"]'`
   (saving runs a signed preflight server-side).
3. Rotate the secret:
   `python3 ../ag-action.py 40184e5270bd3c095f9ca5cd9c86be10913e0e0cb8 rotateAgentSecret '["<agentId>"]'`
   → new secret into `.env`, restart the server (`./restart.sh`).
4. Run preflight:
   `python3 ../ag-action.py 40fa79c832103a73d5f79d0c0d0955bcc33d0c774b preflightAgent '["<agentId>"]'`
   — it must pass before the agent is active.
5. Practice mode (max 10 dispatches/hour) to validate end-to-end.

## Files

- `src/server.mjs` — HTTP handler, HMAC verification (raw body), preflight responder
- `src/circuit.mjs` — verified decision logic + envelope→circuit mapping
- `src/prover.mjs` — snarkjs Groth16 proof generation + local verify + Poseidon self-check
- `src/kurier.mjs` — Kurier submit + poll to Finalized
- `src/hmac.mjs`, `src/seen.mjs` — HMAC helpers, persistent proof_tx seen-set
- `circuits/` — gatekeeper.wasm, gatekeeper_final.zkey, verification_key.json
  (vk_hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)
- `test/harness.mjs` — local replay harness
- `start.sh`, `tunnel-ngrok.sh`, `restart.sh` — run / expose / restart

Secrets are loaded from the environment only (`.env`, mode 600).
Never commit `.env`. Never log secrets.
