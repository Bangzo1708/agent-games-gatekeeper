// Local Groth16 proving with snarkjs (gatekeeper.wasm + gatekeeper_final.zkey).
// Every proof is verified locally against the verification key before it is
// returned — never send a proof we have not verified ourselves.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { selfCheck } from './circuit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || join(HERE, '..', 'circuits');
const WASM_PATH = join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const VKEY_PATH = join(CIRCUITS_DIR, 'verification_key.json');

let vkeyCache = null;
export function loadVkey() {
  if (!vkeyCache) vkeyCache = JSON.parse(readFileSync(VKEY_PATH, 'utf8'));
  return vkeyCache;
}

// Generate { proof, publicSignals } for the given circuit inputs.
// Verifies the proof locally AND self-checks public[0] == Poseidon(salt, taskId)
// before returning — never send a proof we have not verified ourselves.
// Throws on any proving/verification/self-check failure.
export async function generateProof(circuitInputs, salt, taskIdField) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    WASM_PATH,
    ZKEY_PATH,
  );
  const ok = await snarkjs.groth16.verify(loadVkey(), publicSignals, proof);
  if (!ok) throw new Error('local proof verification failed');
  if (salt !== undefined && taskIdField !== undefined) {
    const check = await selfCheck(publicSignals, salt, taskIdField);
    if (!check.ok) throw new Error(`self-check failed: public[0] ${check.got} != Poseidon(salt,taskId) ${check.expected}`);
  }
  return { proof, publicSignals: publicSignals.map(String) };
}
