// Circuit mapping + verified decision logic for the Proof Gatekeeper circuit.
// Reverse-engineered 15 Nov 2026 (see ../circuit-probe/MAPPING.md).
// Field: BN128 SCALAR field r (NOT the base field p). snarkjs reduces every
// input mod r automatically; buildInputs() reduces explicitly anyway.
//
// Verified rules (decision-matrix sweeps against the live circuit):
//   APPROVE iff proofVk == registeredVk (mod r) AND publicBalance >= minimum
//   AND currentBlock < expiryBlock (STRICT — the expiry block itself is
//   expired) AND recipient == conditionRecipient AND amount <= maxTransfer
//   AND proof_tx not seen before.
//   Provability guard: each compared pair must differ by < 2^32, else the
//   circuit can prove NEITHER decision — answer the correct decision with
//   NO proof attached.
//   PROOF_REUSED is a platform rule, not a circuit check: respond REJECT
//   with NO proof (the circuit would refuse a false REJECT anyway — witness
//   assert at GatekeeperEvaluation_79 line 102).
//   task_id -> field element: keccak256(utf8(task_id)) mod r (best candidate;
//   the platform publishes no mapping — confirmed or corrected by the first
//   practice task; override with TASK_ID_ENCODING=keccak-mod-p |
//   numeric-suffix | poseidon-bytes).
//   Salt: fresh random 128-bit per task, never reused, never logged.
//   Public signals (snarkjs order): [0]=Poseidon([salt,taskId]), [1]=regVk
//   mod r, [2]=proofVk mod r, [3]=minimum, [4]=publicBalance, [5]=expiry,
//   [6]=current, [7]=recipient, [8]=conditionRecipient, [9]=amount,
//   [10]=maxTransfer, [11]=decision (1 APPROVE / 0 REJECT), [12]=taskId.
import crypto from 'node:crypto';
import { keccak256 } from 'js-sha3';
import { buildPoseidon } from 'circomlibjs';

export const FIELD_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const FIELD_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const MAX_DIFF = 2n ** 32n;

export const REGISTERED_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

export function randomSalt() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
}

export function taskIdToField(taskId, encoding) {
  const enc = encoding || process.env.TASK_ID_ENCODING || 'keccak-mod-r';
  const s = String(taskId);
  switch (enc) {
    case 'keccak-mod-r':
      return (BigInt('0x' + keccak256(s)) % FIELD_R).toString();
    case 'keccak-mod-p':
      return (BigInt('0x' + keccak256(s)) % FIELD_P).toString();
    case 'numeric-suffix': {
      const suffix = s.replace(/^gk_/, '').replace(/_/g, '');
      return (BigInt('0x' + suffix) % FIELD_R).toString();
    }
    case 'poseidon-bytes':
      throw new Error('poseidon-bytes is async — use taskIdToFieldPoseidon()');
    default:
      throw new Error(`unknown taskId encoding: ${enc}`);
  }
}

export async function taskIdToFieldPoseidon(taskId) {
  const poseidon = await buildPoseidon();
  const bytes = [...new TextEncoder().encode(String(taskId))].map(BigInt);
  return poseidon.F.toObject(poseidon(bytes)).toString();
}

const HEX_ADDR = /^0x[0-9a-fA-F]{40}$/;
const HEX_ANY = /^0x[0-9a-fA-F]+$/;

function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) return null;
    return BigInt(v);
  }
  if (typeof v === 'string') {
    const s = v.trim();
    if (/^\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  }
  return null;
}

// Validate envelope shape first; malformed input fails closed as MALFORMED.
// Returns { decision: 'APPROVE'|'REJECT', reason_code, provable, needsProof }.
// needsProof is false for PROOF_REUSED / MALFORMED / unprovable — the
// response carries the decision with NO proof in those cases.
export function decide(input, seenProofTx = new Set()) {
  const fail = (code, provable = true) => ({
    decision: 'REJECT', reason_code: code, provable, needsProof: false,
  });
  if (!input || typeof input !== 'object') return fail('MALFORMED');
  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer'];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null || input[f] === '') {
      return fail('MALFORMED');
    }
  }
  if (!HEX_ANY.test(input.registered_vk) || !HEX_ANY.test(input.proof_vk)) return fail('MALFORMED');
  if (!HEX_ADDR.test(input.recipient) || !HEX_ADDR.test(input.condition_recipient)) return fail('MALFORMED');
  const vals = {
    minimum: toBigInt(input.minimum),
    balance: toBigInt(input.public_balance),
    expiry: toBigInt(input.expiry_block),
    current: toBigInt(input.current_block),
    amount: toBigInt(input.amount),
    maxTransfer: toBigInt(input.max_transfer),
  };
  if (Object.values(vals).some((x) => x === null)) return fail('MALFORMED');

  const regVk = BigInt(input.registered_vk) % FIELD_R;
  const proofVk = BigInt(input.proof_vk) % FIELD_R;
  const recipient = BigInt(input.recipient);
  const condRecipient = BigInt(input.condition_recipient);

  // Provability guard (verified by sweep): |diff| < 2^32 for each pair.
  const diffs = [vals.balance - vals.minimum, vals.expiry - vals.current, vals.amount - vals.maxTransfer];
  const provable = diffs.every((d) => (d < 0n ? -d : d) < MAX_DIFF);

  // Reason order matches the verified artifact (PROOF_REUSED before expiry).
  let reason = null;
  if (regVk !== proofVk) reason = 'VK_SUBSTITUTION';
  else if (vals.balance < vals.minimum) reason = 'THRESHOLD_MISMATCH';
  else if (typeof input.proof_tx === 'string' && input.proof_tx && seenProofTx.has(input.proof_tx.toLowerCase())) reason = 'PROOF_REUSED';
  else if (vals.current >= vals.expiry) reason = 'EXPIRED_CONDITION'; // STRICT <: expiry block itself is expired
  else if (recipient !== condRecipient) reason = 'RECIPIENT_MISMATCH';
  else if (vals.amount > vals.maxTransfer) reason = 'AMOUNT_OVERFLOW';

  // Extra hardening (env-togglable): also require registered_vk to equal the
  // event's published key, so a wholesale substitution cannot pass.
  const strictVk = (process.env.STRICT_VK || 'true').toLowerCase() !== 'false';
  if (reason === null && strictVk && input.registered_vk.toLowerCase() !== REGISTERED_VK_HASH) {
    reason = 'VK_SUBSTITUTION';
  }

  if (reason === null) {
    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', provable, needsProof: provable };
  }
  if (reason === 'PROOF_REUSED') {
    return { decision: 'REJECT', reason_code: reason, provable, needsProof: false };
  }
  return { decision: 'REJECT', reason_code: reason, provable, needsProof: provable };
}

// Build the 13-field snarkjs input object. salt: fresh random per task.
// decision: 'APPROVE' (1) or 'REJECT' (0) — MUST equal decide().decision,
// otherwise witness generation asserts and no proof is produced.
export function buildInputs(input, decision, taskId, salt) {
  return {
    registeredVkHash: (BigInt(input.registered_vk) % FIELD_R).toString(),
    proofVkHash: (BigInt(input.proof_vk) % FIELD_R).toString(),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    expiryBlock: Number(input.expiry_block),
    currentBlock: Number(input.current_block),
    recipient: BigInt(input.recipient).toString(),
    conditionRecipient: BigInt(input.condition_recipient).toString(),
    amount: BigInt(input.amount).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    salt: (BigInt(salt) % FIELD_R).toString(),
    decision: decision === 'APPROVE' ? 1 : 0,
    taskId: taskIdToField(taskId),
  };
}

// Self-check before submitting: public[0] MUST equal Poseidon([salt, taskId]).
export async function selfCheck(publicSignals, salt, taskIdField) {
  const poseidon = await buildPoseidon();
  const expected = poseidon.F.toObject(
    poseidon([BigInt(salt) % FIELD_R, BigInt(taskIdField) % FIELD_R]),
  ).toString();
  return { ok: publicSignals[0] === expected, expected, got: publicSignals[0] };
}
