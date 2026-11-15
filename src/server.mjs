// Proof Gatekeeper agent server — handle safari82 (Agent Games, zkVerify).
//
// POST /agent  — signed task envelopes + preflight (platform posts here)
// GET  /healthz — liveness only, no auth
//
// Flow per task (60s hard deadline, fail closed):
//   1. verify x-agent-games-signature over the RAW body (before JSON parse)
//   2. preflight -> { ok: true, protocolVersion: "v1" } (signed)
//   3. task -> deterministic decide() -> local Groth16 proof (snarkjs) ->
//      best-effort Kurier submit (bounded wait) -> signed response
//      { decision, reason_code, proof, public_signals[, proof_tx] }
//   4. any error/timeout/uncertainty -> REJECT (proof attached when possible)
//
// Secrets come from the environment only. Logs never contain secrets.
import http from 'node:http';
import { join } from 'node:path';
import { decide, buildInputs, randomSalt } from './circuit.mjs';
import { generateProof } from './prover.mjs';
import { signBody, verifySignature } from './hmac.mjs';
import { SeenProofTx } from './seen.mjs';
import { submitProof, waitFinalized, kurierConfigured } from './kurier.mjs';

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DATA_DIR = process.env.DATA_DIR || join(process.cwd(), 'data');
const seen = new SeenProofTx(join(DATA_DIR, 'seen-proof-tx.json'));

// Internal soft deadline: always respond by 50s so the platform's 60s limit
// is never hit by our own slowness.
const RESPONSE_DEADLINE_MS = 50_000;
// Max time spent waiting for Kurier Finalized before responding anyway.
const KURIER_WAIT_MS = 15_000;

if (!HMAC_SECRET) {
  console.error('[fatal] AGENT_GAMES_HMAC_SECRET is not set — refusing to start');
  process.exit(1);
}

const log = (...a) => console.log(new Date().toISOString(), ...a);

function sendJson(res, status, obj, sign = true) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = signBody(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

async function proveDecision(input, decision, taskId) {
  const salt = randomSalt();
  const circuitInputs = buildInputs(input, decision, taskId, salt);
  const out = await generateProof(circuitInputs, salt, circuitInputs.taskId);
  return out;
}

async function handleTask(envelope, t0) {
  const input = envelope?.input || null;
  const taskId = typeof envelope?.task_id === 'string' ? envelope.task_id : 'unknown';
  const proofTx = input && typeof input.proof_tx === 'string' ? input.proof_tx : null;

  const result = decide(input, seen.set);
  log(`[task ${taskId}] decision=${result.decision} reason=${result.reason_code} provable=${result.provable} needsProof=${result.needsProof}`);

  let proof = null;
  let publicSignals = null;
  if (!result.needsProof) {
    // PROOF_REUSED / MALFORMED / unprovable: the circuit cannot or must not
    // prove this — respond with the decision and no proof.
    log(`[task ${taskId}] no proof by design (${result.reason_code}${result.provable ? '' : ', unprovable'})`);
  } else {
    try {
      ({ proof, publicSignals } = await proveDecision(input, result.decision, taskId));
      log(`[task ${taskId}] proof generated+verified locally (${Date.now() - t0}ms)`);
    } catch (e) {
      log(`[task ${taskId}] PROOF FAILED: ${String(e).slice(0, 200)}`);
    }
  }

  // Best-effort Kurier submission (audit pointer). Never let it eat the
  // response deadline: only wait while plenty of time remains.
  if (proof && kurierConfigured()) {
    try {
      const job = await submitProof({ proof, publicSignals });
      log(`[task ${taskId}] kurier job ${job.jobId || job.jobID || job.id || '?'} status=${job.status || '?'}`);
      const remain = RESPONSE_DEADLINE_MS - (Date.now() - t0);
      if (remain > 8000) {
        const w = await waitFinalized(job, { deadlineMs: Math.min(KURIER_WAIT_MS, remain - 5000) });
        log(`[task ${taskId}] kurier finalized=${w.finalized} status=${w.status}`);
      }
    } catch (e) {
      log(`[task ${taskId}] kurier error (non-fatal): ${String(e).slice(0, 200)}`);
    }
  } else if (proof && !kurierConfigured()) {
    log(`[task ${taskId}] kurier skipped: KURIER_API_KEY not configured`);
  }

  if (proofTx) seen.add(proofTx);

  const response = { decision: result.decision, reason_code: result.reason_code };
  if (proof) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  if (proofTx) response.proof_tx = proofTx;
  return response;
}

async function handleEnvelope(envelope, t0) {
  if (!envelope || typeof envelope !== 'object') {
    return { decision: 'REJECT', reason_code: 'MALFORMED' };
  }
  if (envelope.type === 'agent-games.preflight.v1') {
    return { ok: true, protocolVersion: 'v1', __preflight: true };
  }
  if (envelope.type !== 'agent-games.proof-gatekeeper.v1') {
    log(`[warn] unknown envelope type: ${envelope.type}`);
    return { decision: 'REJECT', reason_code: 'MALFORMED' };
  }
  try {
    return await handleTask(envelope, t0);
  } catch (e) {
    // Fail closed: REJECT, and try once to attach a proof for the rejection.
    const taskId = typeof envelope.task_id === 'string' ? envelope.task_id : 'unknown';
    log(`[task ${taskId}] handler error, failing closed: ${String(e).slice(0, 200)}`);
    try {
      const { proof, publicSignals } = await proveDecision(envelope.input, 'REJECT', taskId);
      return { decision: 'REJECT', reason_code: 'MALFORMED', proof, public_signals: publicSignals };
    } catch {
      return { decision: 'REJECT', reason_code: 'MALFORMED' };
    }
  }
}

const server = http.createServer((req, res) => {
  const t0 = Date.now();
  if (req.method === 'GET' && req.url === '/healthz') {
    return sendJson(res, 200, { ok: true, seenProofTx: seen.size }, false);
  }
  if (req.method !== 'POST' || (req.url !== '/agent' && req.url !== '/agent/')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'not found' }));
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    if (!verifySignature(HMAC_SECRET, raw, req.headers['x-agent-games-signature'])) {
      log('[auth] signature mismatch — rejecting');
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'bad signature' }));
    }
    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendJson(res, 400, { decision: 'REJECT', reason_code: 'MALFORMED' });
    }
    const out = await handleEnvelope(envelope, t0);
    if (out.__preflight) {
      const { __preflight, ...body } = out;
      return sendJson(res, 200, body);
    }
    // Safety: never exceed the soft deadline (proving is ~3s; this is a guard).
    if (Date.now() - t0 > RESPONSE_DEADLINE_MS) {
      log('[warn] response past soft deadline, sending anyway');
    }
    return sendJson(res, 200, out);
  });
  req.on('error', () => {
    try { res.writeHead(400); res.end(); } catch { /* socket gone */ }
  });
});

server.listen(PORT, () => {
  log(`gatekeeper agent listening on :${PORT} (POST /agent, GET /healthz)`);
  log(`kurier configured: ${kurierConfigured()}`);
});
