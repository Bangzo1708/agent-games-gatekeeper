// Persistent seen-set for proof_tx values (PROOF_REUSED trap defense).
// Stored as a JSON array in a file (default ./data/seen-proof-tx.json) so a
// restart does not forget which proof references were already used.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

export class SeenProofTx {
  constructor(filePath) {
    this.filePath = filePath || join(process.cwd(), 'data', 'seen-proof-tx.json');
    this.set = new Set();
    try {
      if (existsSync(this.filePath)) {
        const arr = JSON.parse(readFileSync(this.filePath, 'utf8'));
        if (Array.isArray(arr)) for (const x of arr) this.set.add(String(x).toLowerCase());
      }
    } catch { /* corrupt/missing file -> start empty, fail closed elsewhere */ }
  }

  has(tx) { return !!tx && this.set.has(String(tx).toLowerCase()); }

  add(tx) {
    if (!tx) return;
    this.set.add(String(tx).toLowerCase());
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });
      writeFileSync(this.filePath, JSON.stringify([...this.set], null, 2));
    } catch { /* persistence failure must not break the response path */ }
  }

  get size() { return this.set.size; }
}
