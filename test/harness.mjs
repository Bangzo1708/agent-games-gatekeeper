// Local test harness: replays sample envelopes against the verified decision
// logic and the real prover (no network, no Kurier, no HMAC secret needed).
// Usage: node test/harness.mjs
// Exit 0 only if every case decides as expected AND every proof verifies.
import { decide, buildInputs, randomSalt, REGISTERED_VK_HASH } from '../src/circuit.mjs';
import { generateProof } from '../src/prover.mjs';

const VK = REGISTERED_VK_HASH;
const OTHER_VK = '0x1111111111111111111111111111111111111111111111111111111111111111';
const RECIP = '0x' + '42'.repeat(20);
const RECIP_OTHER = '0x' + '42'.repeat(19) + '43';

const base = {
  registered_vk: VK,
  proof_vk: VK,
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: RECIP,
  condition_recipient: RECIP,
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xa8b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2',
};

// [name, input, wantDecision, wantReason, wantNeedsProof, wantProvable]
const cases = [
  ['VALID_CONDITION', { ...base }, 'APPROVE', 'VALID_CONDITION', true, true],
  ['VK_SUBSTITUTION', { ...base, proof_vk: OTHER_VK }, 'REJECT', 'VK_SUBSTITUTION', true, true],
  ['THRESHOLD_MISMATCH', { ...base, public_balance: '999' }, 'REJECT', 'THRESHOLD_MISMATCH', true, true],
  ['THRESHOLD_BOUNDARY (= minimum)', { ...base, public_balance: '1000' }, 'APPROVE', 'VALID_CONDITION', true, true],
  ['EXPIRED_CONDITION', { ...base, current_block: 8430001 }, 'REJECT', 'EXPIRED_CONDITION', true, true],
  // STRICT expiry: current == expiry is EXPIRED, not valid.
  ['EXPIRY_BOUNDARY (= expiry)', { ...base, current_block: 8430000 }, 'REJECT', 'EXPIRED_CONDITION', true, true],
  ['EXPIRY_JUST_BEFORE', { ...base, current_block: 8429999 }, 'APPROVE', 'VALID_CONDITION', true, true],
  ['RECIPIENT_MISMATCH', { ...base, recipient: RECIP_OTHER }, 'REJECT', 'RECIPIENT_MISMATCH', true, true],
  ['AMOUNT_OVERFLOW', { ...base, amount: '1001' }, 'REJECT', 'AMOUNT_OVERFLOW', true, true],
  ['AMOUNT_BOUNDARY (= max)', { ...base, amount: '1000' }, 'APPROVE', 'VALID_CONDITION', true, true],
  ['PROOF_REUSED (no proof)', { ...base, proof_tx: '0xdeadbeef' }, 'REJECT', 'PROOF_REUSED', false, true],
  ['MALFORMED (missing amount)', { ...base, amount: undefined }, 'REJECT', 'MALFORMED', false, true],
  // Provability guard: balance-minimum = 2^32 exactly -> unprovable either way.
  ['UNPROVABLE (diff = 2^32)', { ...base, minimum: '1000', public_balance: String(1000 + 2 ** 32) }, 'APPROVE', 'VALID_CONDITION', false, false],
];

let failures = 0;
const seen = new Set(['0xdeadbeef']);

for (const [name, input, wantDecision, wantReason, wantNeedsProof, wantProvable] of cases) {
  const clean = Object.fromEntries(Object.entries(input).filter(([, v]) => v !== undefined));
  const r = decide(clean, seen);
  const ok = r.decision === wantDecision && r.reason_code === wantReason
    && r.needsProof === wantNeedsProof && r.provable === wantProvable;
  console.log(`${ok ? 'PASS' : 'FAIL'} decide ${name}: got ${r.decision}/${r.reason_code}/needsProof=${r.needsProof}/provable=${r.provable}, want ${wantDecision}/${wantReason}/needsProof=${wantNeedsProof}/provable=${wantProvable}`);
  if (!ok) failures++;
}

// Prove two cases end-to-end (valid APPROVE + one REJECT) with the real circuit.
for (const [name, input, wantDecision] of [
  ['VALID_CONDITION', base, 'APPROVE'],
  ['VK_SUBSTITUTION', { ...base, proof_vk: OTHER_VK }, 'REJECT'],
]) {
  const t0 = Date.now();
  try {
    const salt = randomSalt();
    const ci = buildInputs(input, wantDecision, `gk_test_${name}`, salt);
    const { proof, publicSignals } = await generateProof(ci, salt, ci.taskId);
    console.log(`PASS prove ${name}: ${wantDecision} proof verifies locally + self-check OK (${Date.now() - t0}ms), public[11]=${publicSignals[11]} (decision), public[12]=${publicSignals[12].slice(0, 20)}... (taskId)`);
  } catch (e) {
    console.log(`FAIL prove ${name}: ${String(e).slice(0, 300)}`);
    failures++;
  }
}

console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
