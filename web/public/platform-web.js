// Web implementation of the UI <-> platform contract (ARCHITECTURE.md §6).
// The UI (app.js) talks ONLY to this contract. Tauri builds replace
// platform.js with `export * from './platform-tauri.js'`, which implements the
// same functions via native commands, so secrets never enter JS at all there.

import init, * as pg from './pkg/norea_web.js';
import * as custody from './custody.js';

export async function ready() { await init(); }

export const prfAvailable = () => custody.prfAvailable();
export const hasKey = () => custody.hasCustody();
export const exportBackup = () => custody.exportBackup();
export const importBackup = bytes => custody.importBackup(bytes);

/** {method, fingerprint, hardwareDuringSigning} or null. */
export async function keyInfo() {
  const vk = await custody.publicKey();
  if (!vk) return null;
  return {
    method: await custody.method(),
    fingerprint: pg.sha256Hex(vk).slice(0, 16),
    hardwareDuringSigning: false, // web: key is in page memory while signing (ADR-006)
  };
}

/** Creates the signing key and returns the encrypted backup bytes. */
export async function setupKey({ passphrase } = {}) {
  await custody.setup({ passphrase });
  return custody.exportBackup();
}

/** Returns { marked: Uint8Array, evidenceJson: string }. Input is never modified. */
export async function protect({ input, datasetId, n, forbiddenAddrs = [], passphrase }) {
  return custody.withSecrets(async ({ masterK, seed }) => {
    const kd = pg.deriveDatasetKey(masterK, datasetId);
    const m = pg.markParcels(input, kd, n, JSON.stringify(forbiddenAddrs));
    try {
      const marked = m.bytes;
      const evidenceJson = pg.buildEvidence(marked, m.attempts, datasetId, kd, new Date().toISOString(), seed);
      return { marked, evidenceJson };
    } finally {
      m.free();
      kd.fill(0);
    }
  }, { passphrase });
}

/** Returns the parsed report. */
export async function check({ suspect, evidenceJson, passphrase }) {
  const ev = JSON.parse(evidenceJson);
  return custody.withSecrets(async ({ masterK }) => {
    const kd = pg.deriveDatasetKey(masterK, ev.dataset_id);
    try { return JSON.parse(pg.checkCopy(suspect, kd, evidenceJson)); } finally { kd.fill(0); }
  }, { passphrase });
}

/** Needs no secrets: anyone holding the evidence can run it. */
export const verifyEvidence = evidenceJson => pg.verifyEvidence(evidenceJson);

/** Save bytes as a file. Tauri: dialog.save + fs.writeFile instead. */
export async function saveFile(name, bytes) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/json' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

/** Yes/no prompt. Tauri: dialog.ask instead of window.confirm. */
export async function confirmAction(message) {
  return window.confirm(message);
}

/** Every platform implementation must export exactly these. */
export const CONTRACT = ['ready', 'prfAvailable', 'hasKey', 'keyInfo', 'setupKey', 'exportBackup',
  'importBackup', 'protect', 'check', 'verifyEvidence', 'saveFile', 'confirmAction'];
