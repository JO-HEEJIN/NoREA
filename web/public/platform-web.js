// Web implementation of the UI <-> platform contract v1
// (Fable_5_1/docs/protocol/platform-contract.md, 17 functions + CONTRACT).
// The UI (app.js) calls only these, through platform.js. Tauri builds replace
// platform.js with './platform-tauri.js' and secrets never enter JS there.
//
// Every function is async and throws an Error whose message is a Korean sentence
// for the user (no secrets, paths or stacks). `error.code` is always one of the
// contract codes: KEY_MISSING, KEY_EXISTS, BAD_PASSPHRASE, PRF_UNSUPPORTED, CANCELLED,
// BAD_INPUT, NO_MARKER, CANARY_EXHAUSTED, BAD_EVIDENCE, BAD_DISCLOSURE,
// ANCHOR_UNAVAILABLE, BACKUP_INVALID. Only an unexpected internal failure (a bug,
// IndexedDB unavailable) has no code. `error.detail` keeps the core's English
// technical message (CORE-API: it carries no secrets, input values or paths).
//
// Secrets: custody.withSecrets() unwraps K and seed, this file hands them to one
// WASM call (protect / check / disclose), and custody fills them with 0 (ADR-0012).

import init, * as wasm from './pkg/norea_web.js';
import * as custody from './custody.js';

/** Every platform implementation exports exactly these 17 functions. */
export const CONTRACT = ['ready', 'capabilities', 'hasKey', 'keyInfo', 'setupKey', 'deleteKey', 'exportBackup',
  'importBackup', 'inspect', 'protect', 'anchor', 'check', 'disclose', 'verifyEvidence', 'verifyDisclosure',
  'saveFile', 'confirmAction'];

// ---------------------------------------------------------------- errors
// core ErrorCode (or ANCHOR_UNAVAILABLE) -> [contract code, Korean message]
const CORE_ERRORS = {
  BadInput: ['BAD_INPUT', 'The input file or options are invalid.'],
  NoMarker: ['NO_MARKER', 'No marker fields could be chosen for matching. Pick marker fields yourself.'],
  CanaryExhausted: ['CANARY_EXHAUSTED', 'This data cannot hold the requested number of canaries. Lower the count or pick different markers.'],
  BadEvidence: ['BAD_EVIDENCE', 'The evidence file is invalid or was tampered with.'],
  BadSignature: ['BAD_EVIDENCE', 'The signature could not be created or checked.'],
  BadBlob: ['BAD_EVIDENCE', 'The canaries in this evidence cannot be opened with this key. Wrong key, or the evidence was tampered with.'],
  BadDisclosure: ['BAD_DISCLOSURE', 'The disclosure request or file is invalid.'],
  BadAnchor: ['BAD_EVIDENCE', 'The anchor is invalid.'],
  ANCHOR_UNAVAILABLE: ['ANCHOR_UNAVAILABLE', 'Time anchors are not supported yet.'],
};

function platformError(code, message, detail) {
  const e = new Error(message);
  if (code) e.code = code;
  if (detail) e.detail = detail;
  e.platform = true;
  return e;
}
const badInput = message => platformError('BAD_INPUT', message);
const badEvidence = message => platformError('BAD_EVIDENCE', message);
const badDisclosure = message => platformError('BAD_DISCLOSURE', message);

/** WASM throws `CODE: message` (CORE-API §2). Anything else becomes a generic message. */
function normalize(e) {
  if (e && e.platform) return e;
  const m = /^([A-Za-z_]+): ([\s\S]*)$/.exec(String(e?.message ?? ''));
  if (m && CORE_ERRORS[m[1]]) {
    const [code, ko] = CORE_ERRORS[m[1]];
    return platformError(code, ko, `${m[1]}: ${m[2]}`);
  }
  return platformError(null, 'An unexpected error occurred during processing.');
}
const guard = fn => async (...args) => {
  try { return await fn(...args); } catch (e) { throw normalize(e); }
};

// ---------------------------------------------------------------- argument checks
function bytes(x, what) {
  if (!(x instanceof Uint8Array)) throw badInput(`${what} must be file bytes (Uint8Array).`);
  return x;
}
function text(x, what) {
  if (typeof x !== 'string') throw badInput(`${what} must be a string.`);
  return x;
}
function evidenceText(x) {
  if (typeof x !== 'string') throw badEvidence('evidence must be a JSON string.');
  return x;
}
function disclosureText(x) {
  if (typeof x !== 'string') throw badDisclosure('disclosure must be a JSON string.');
  return x;
}
function format(x) {
  if (x === undefined || x === null) return undefined;
  if (x !== 'json' && x !== 'csv') throw badInput('format must be json or csv.');
  return x;
}
function strings(x, what) {
  if (x === undefined || x === null) return null;
  if (!Array.isArray(x) || !x.every(s => typeof s === 'string')) throw badInput(`${what} must be an array of strings.`);
  return x;
}
const camel = s => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
function camelKeys(v) {
  if (Array.isArray(v)) return v.map(camelKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [camel(k), camelKeys(x)]));
  return v;
}

// ---------------------------------------------------------------- 1-4
let initPromise = null;
/** WASM init. Call before anything else. */
export const ready = guard(async () => { initPromise ??= init(); await initPromise; });

/** hardwareDuringSigning: web signs with the seed in page memory (ADR-0006). No relay until WP-08. */
export const capabilities = guard(async () => ({
  platform: 'web',
  prf: await custody.prfAvailable(),
  hardwareDuringSigning: false,
  anchorRelay: null,
}));

export const hasKey = guard(() => custody.hasCustody());

/**
 * `{method, fingerprint, hardwareDuringSigning, createdClaim, persisted}` or null.
 * fingerprint = sha256(vk)[0..16 hex]; persisted = true | false | "unknown" (custody-web-v1 §2).
 */
export const keyInfo = guard(async () => {
  const i = await custody.info();
  if (!i) return null;
  return {
    method: i.method, fingerprint: wasm.sha256Hex(i.vk).slice(0, 16), hardwareDuringSigning: false,
    createdClaim: i.createdClaim, persisted: await custody.persistedState(),
  };
});

// ---------------------------------------------------------------- 5-8 key custody
/** New K + seed. With `passphrase`: Argon2id; without: WebAuthn PRF passkey. Returns the encrypted backup bytes. */
export const setupKey = guard(async ({ passphrase } = {}) => {
  await custody.setup({ passphrase });
  return custody.exportBackup();
});

export const deleteKey = guard(() => custody.remove());

/** `norea.custody-backup.v1` bytes. */
export const exportBackup = guard(() => custody.exportBackup());

/** Validates (custody-web-v1 §3) and stores. Overwrites an existing key: the UI confirms first. */
export const importBackup = guard(b => custody.importBackup(bytes(b, 'Backup file')));

// ---------------------------------------------------------------- 9-10
/** InspectResult (no secrets). */
export const inspect = guard(async ({ input, format: f } = {}) =>
  JSON.parse(wasm.inspect(bytes(input, 'Input file'), format(f))));

/** `{marked, evidenceJson, evidenceId, summary}`. The input is never modified. */
export const protect = guard(async ({ input, format: f, datasetId, n, markerFields, exclusions, passphrase } = {}) => {
  bytes(input, 'Input file');
  text(datasetId, 'Dataset ID');
  if (!Number.isInteger(n) || n < 1) throw badInput('The canary count must be an integer of at least 1.');
  // Parse first (no secrets): a bad file fails before the key is unlocked, and gives `rows`.
  const shape = JSON.parse(wasm.inspect(input, format(f)));
  const optionsJson = JSON.stringify({
    n, markerFields: strings(markerFields, 'markerFields'), exclusions: strings(exclusions, 'exclusions') ?? [], format: shape.format,
  });
  const createdClaim = custody.claimNow();
  const { marked, evidenceJson } = await custody.withSecrets((masterK, seed) => {
    const r = wasm.protect(input, masterK, seed, datasetId, optionsJson, createdClaim);
    try { return { marked: r.marked, evidenceJson: r.evidenceJson }; } finally { r.free(); }
  }, { passphrase });
  const ev = JSON.parse(evidenceJson);
  const summary = {
    rows: shape.rows, canaries: ev.canary_count, markers: ev.marker_fields,
    threshold: Math.min(2, ev.marker_fields.length), format: ev.format, evidenceId: ev.evidence_id,
  };
  return { marked, evidenceJson, evidenceId: ev.evidence_id, summary };
});

// ---------------------------------------------------------------- 11 anchor (WP-08)
/** Not available until WP-08 (relay + core anchor.rs). */
export const anchor = guard(async () => {
  throw platformError('ANCHOR_UNAVAILABLE', CORE_ERRORS.ANCHOR_UNAVAILABLE[1]);
});

// ---------------------------------------------------------------- 12-13 (K needed)
/** norea.check-report.v1 object. */
export const check = guard(async ({ suspect, evidenceJson, passphrase } = {}) => {
  bytes(suspect, 'Suspicious copy');
  wasm.verifyEvidence(evidenceText(evidenceJson)); // structure check before unlocking the key
  const report = await custody.withSecrets(masterK => wasm.check(suspect, masterK, evidenceJson), { passphrase });
  return JSON.parse(report);
});

/** `{disclosureJson}` (norea.disclosure.v1). `indices` omitted = every matched canary. */
export const disclose = guard(async ({ evidenceJson, suspect, indices, suspectMeta, passphrase } = {}) => {
  bytes(suspect, 'Suspicious copy');
  wasm.verifyEvidence(evidenceText(evidenceJson));
  if (indices !== undefined && indices !== null &&
      (!Array.isArray(indices) || !indices.every(i => Number.isInteger(i) && i >= 0))) {
    throw badDisclosure('indices must be an array of non-negative integers.');
  }
  const m = suspectMeta ?? {};
  const claim = k => (m[k] === undefined || m[k] === null ? '' : text(m[k], k));
  const metaJson = JSON.stringify({
    sourceClaim: claim('sourceClaim'), capturedClaim: claim('capturedClaim'), captureMethodClaim: claim('captureMethodClaim'),
  });
  const indicesJson = indices ? JSON.stringify(indices) : 'null';
  const createdClaim = custody.claimNow();
  const disclosureJson = await custody.withSecrets(
    masterK => wasm.disclose(evidenceJson, masterK, suspect, indicesJson, metaJson, createdClaim, false), { passphrase });
  return { disclosureJson };
});

// ---------------------------------------------------------------- 14-15 (no secrets)
/** EvidenceVerification `{signatureOk, evidenceIdOk, blobHashOk, anchors: [...], hasAnchors}`. */
export const verifyEvidence = guard(async evidenceJson =>
  camelKeys(JSON.parse(wasm.verifyEvidence(evidenceText(evidenceJson)))));

/**
 * norea.disclosure-report.v1 object, unchanged. PASS is
 * `report.verdict.integrity_ok && report.verdict.all_reproduced` (same rule as norea-verify exit 0);
 * a thrown BAD_DISCLOSURE (or BAD_EVIDENCE) is a structural error (exit 2).
 */
export const verifyDisclosure = guard(async (disclosureJson, suspect) =>
  JSON.parse(wasm.verifyDisclosure(disclosureText(disclosureJson), bytes(suspect, 'Suspicious copy'))));

// ---------------------------------------------------------------- 16-17 UI helpers
export const saveFile = guard(async (name, data, mime = 'application/octet-stream') => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bytes(data, 'File to save')], { type: mime }));
  a.download = text(name, 'File name');
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
});

export const confirmAction = guard(async message => window.confirm(String(message)));
