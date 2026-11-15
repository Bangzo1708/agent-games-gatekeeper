// Kurier REST client (https://api.kurier.xyz/api/v1).
// Submit a Groth16 proof, poll the job until Finalized (or a caller deadline).
// No API key here yet: KURIER_API_KEY is loaded from the environment at call
// time; submitProof throws a clear error when it is missing so the server can
// still respond with the local proof (proof_tx is optional in the response).

const API_URL = process.env.KURIER_API_URL || 'https://api.kurier.xyz/api/v1';

// vk hash of the gatekeeper circuit, registered on zkVerify mainnet.
export const REGISTERED_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function kurierConfigured() {
  return Boolean(process.env.KURIER_API_KEY);
}

// Submit {proof, publicSignals} (snarkjs format). Returns the job object
// ({jobId/jobID, status, ...}) as returned by Kurier.
export async function submitProof({ proof, publicSignals, vk = REGISTERED_VK_HASH }) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) throw new Error('KURIER_API_KEY not configured');
  const res = await fetch(`${API_URL}/submit-proof/${apiKey}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      proofType: 'groth16',
      vkRegistered: true,
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      proofData: { proof, publicSignals, vk },
    }),
  });
  const text = await res.text();
  let job;
  try { job = JSON.parse(text); } catch { job = { raw: text }; }
  if (!res.ok) {
    throw new Error(`Kurier submit failed HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return job;
}

// Poll a job until status Finalized, or until deadlineMs elapses.
// Returns { finalized: boolean, status: string, job }.
export async function waitFinalized(job, { deadlineMs = 20000, intervalMs = 2000 } = {}) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) throw new Error('KURIER_API_KEY not configured');
  const jobId = job.jobId || job.jobID || job.id;
  if (!jobId) throw new Error('Kurier job has no id to poll');
  const t0 = Date.now();
  let status = job.status || 'Submitted';
  let last = job;
  while (Date.now() - t0 < deadlineMs) {
    if (status === 'Finalized') return { finalized: true, status, job: last };
    await sleep(intervalMs);
    const res = await fetch(`${API_URL}/jobs/${jobId}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!res.ok) {
      // Transient poll failure: keep waiting until the deadline.
      continue;
    }
    last = await res.json();
    status = last.status || last.state || status;
  }
  return { finalized: status === 'Finalized', status, job: last };
}
