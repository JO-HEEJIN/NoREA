// Pure UI text and view-model helpers for app.js (WP-07).
// No imports, no DOM, no platform calls: everything here turns contract results
// (platform-contract v1 types) into English sentences and plain data that app.js renders.
// tests/ui.node.mjs unit-tests this module in node.
//
// Rules (WP-07 spec): no emoji; technical terms stay English (canary, evidence, anchor,
// passkey, marker); what is not verified is written as "does not prove".

export const PASSPHRASE_MIN = 12;
export const CANARY_MIN = 8;
export const CANARY_MAX = 256;
export const CANARY_DEFAULT = 32;
export const MARKER_MAX = 4;

// ---------------------------------------------------------------- fixed sentences
export const TEXT = {
  hardwareMemory: 'During signing, the key is in this browser\'s memory.',
  hardwareMemoryMore: 'Signing does not happen inside a hardware security device. If you need stronger assurance, use the desktop app (in preparation).',
  storageMayClear: 'The browser may clear the key storage. Keep the backup file in a safe place.',
  storageKept: 'This browser reported that it will keep the key storage. Still keep the backup file separately.',
  prfBackup: 'If you lose the passkey, this backup cannot be opened either. A passkey backup opens only on a device that has the same passkey.',
  prfSecondBackupMissing: 'Creating a second backup wrapped with a passphrase is not available yet. If losing the passkey worries you, create the key with a passphrase instead.',
  keyLoss: 'If you lose the signing key, the canaries in existing evidence cannot be recovered, so you cannot run a check or build a disclosure package for that release.',
  backupForced: 'Creating a key immediately downloads an encrypted backup file (norea-key-backup.json). The file alone cannot open the key; the passphrase or passkey is also required.',
  passphraseRule: `The passphrase must be at least ${PASSPHRASE_MIN} characters. It is never sent anywhere, and if you forget it nobody can recover it.`,
  passphraseMemory: 'The passphrase is cleared from the input field right after use. The browser does not guarantee that the string is wiped from memory immediately.',
  createdClaim: 'The creation time is only a claim from this device\'s clock and does not prove when the key was created.',
  prfUnknown: 'It cannot be known in advance whether this browser supports passkey (PRF). Try the passkey; if it fails, use a passphrase. A failed attempt may leave the newly created passkey unused on the device.',
  prfNo: 'passkey (PRF) is not available in this browser. Use a passphrase.',
  prfYes: 'This browser supports passkey (PRF).',
  jsonReserialize: 'For JSON input, inserting canaries rewrites the whole file. Values stay the same, but output formatting such as indentation and whitespace may change.',
  notStandardJson: 'Not standard JSON (comments, trailing commas, etc.). Remove comments and trailing commas and try again.',
  jsonReadAsCsv: "The file name ends in .json but it did not parse as JSON, so it was read as CSV. Set 'Input format' above to 'Read as JSON' to see where the problem is (line, column).",
  jsonNameButCsv: 'The file name ends in .json but it was detected as CSV. It may be JSON with comments or trailing commas. Fix it to standard JSON and select it again.',
  evidencePrivate: 'Do not publish the evidence file. Publish only the marked file. You need the evidence later to run a check and build a disclosure package; if you lose it, you cannot prove copying of this release.',
  anchorNotConfigured: 'Time anchor: not configured in this deployment. Use the CLI (norea anchor).',
  anchorReady: 'Get an RFC 3161 time anchor from a public TSA through the anchor relay. Only a SHA-256 hash of the signed evidence leaves this browser. Until you anchor it, this evidence does not prove when it was created.',
  anchorButton: 'Get time anchor',
  anchorButtonOff: 'Get time anchor (not configured)',
  noTimeProof: 'This evidence does not prove when it was created.',
  noCaptureProof: 'This product does not prove when or where the copy was obtained (capture time). The source and capture time of the copy are claims and are not verified. Back them up with external evidence such as notarization or a web archive.',
  tsaChain: 'The TSA certificate chain is not verified by this tool (chain_verified: false). To check the chain, run norea-verify --export-anchors and then openssl ts -verify yourself.',
  commitBad: 'This evidence was not made with this signing key, or it was tampered with. The check was not run (0 matched).',
  discloseBefore: 'Disclosed canaries become known to the other party and may be removed from their next copy. Disclose only matched canaries, and preferably only a subset of all canaries.',
  discloseNoSecret: 'This file contains neither the master key nor the signing key. Undisclosed canaries are included only in encrypted form.',
  discloseClaim: 'The three fields below are recorded as the operator\'s claims and are not verified.',
  discloseSubmit: 'Submit the disclosure package together with the copy file used for the check. The verifier needs both files.',
  verifyNoKey: 'This tab works without a signing key. Anyone can verify an evidence file or a disclosure package, and files never leave this browser.',
  evidenceOnly: 'Verifying evidence alone checks only the signature and hashes. Verify matches against a copy with the disclosure package and the copy file.',
  limits: [
    'A copy whose data was rewritten wholesale cannot be caught by canaries.',
    'The guarantee that a canary is a value that does not really exist is complete only when you supply an exclusions file (an official list).',
    'Date-like fields may get dates that do not exist (e.g. February 31).',
    'The generator does not know relationships between fields (e.g. the city in an address and a separate city column). In strongly related data, canaries may be filtered out statistically.',
    'Free-text fields that differ per row get real values copied into canaries, which can expose them as duplicates.',
  ],
};

// ---------------------------------------------------------------- inspect warnings (shape-v1 §6.2)
const q = f => (f ? `Field '${f}'` : 'This field');

/** One English sentence per inspect warning code (canary-record-shape-v1 §6.2, §8). */
export function warningText({ code, field } = {}) {
  switch (code) {
    case 'OPAQUE_FIELD':
      return `${q(field)} has values of irregular shape, so new values cannot be generated and real values are copied into canaries as is. It cannot be used as a marker.`;
    case 'UNIQUE_OPAQUE_COPIED':
      return `${q(field)} is free text that differs per row, so the value copied into a canary duplicates another row of the original exactly. This duplication can expose canaries; a release without this field is recommended.`;
    case 'LOW_FREE_SPACE':
      return `${q(field)} is not suitable as a marker: more than half of the values it could generate are already real values.`;
    case 'NO_FREE_SPACE':
      return `${q(field)} has no free value space, so canaries cannot be generated (a field filled without gaps, like a serial number). Protecting as is will very likely fail. Make a release without this field.`;
    case 'HIGH_MISSING':
      return `${q(field)} is empty in 20% or more of rows, so it was removed from the marker candidates.`;
    case 'NO_MARKER_CANDIDATE':
      return 'No marker candidate could be chosen automatically. Pick marker fields in the table yourself, or use a release with fields that have more varied values.';
    case 'NUMERIC_CODE_LIKE':
      return `${q(field)} holds unique integers of identical length, so it looks like a code (postal code, district code, etc.). The generator does not know the digit structure of codes, so canary values may be statistically distinguishable (a known limitation of this version).`;
    default:
      return `Unknown warning (${String(code)}${field ? `, ${field}` : ''}).`;
  }
}

export const KIND_TEXT = {
  STRING: 'text', NUMERIC: 'number', CATEGORICAL: 'category', BOOL: 'true/false', OPAQUE: 'copied (irregular)', EMPTY: 'empty',
};
/** Only STRING and NUMERIC fields can be markers (shape-v1 §4). */
export const markerEligible = kind => kind === 'STRING' || kind === 'NUMERIC';

/** Rows for the inspect table. `selected` defaults to the suggested markers. */
export function inspectRows(ins, selected = ins.suggestedMarkers) {
  const sel = new Set(selected ?? []);
  const byField = new Map();
  for (const w of ins.warnings ?? []) if (w.field) (byField.get(w.field) ?? byField.set(w.field, []).get(w.field)).push(w);
  return ins.fields.map(f => ({
    name: f.name,
    kind: f.kind,
    kindText: `${f.kind} (${KIND_TEXT[f.kind] ?? '?'})`,
    unique: f.unique ? 'yes' : 'no',
    distinct: String(f.distinct),
    missing: percent(f.pMissing),
    eligible: markerEligible(f.kind),
    checked: sel.has(f.name) && markerEligible(f.kind),
    warnings: (byField.get(f.name) ?? []).map(warningText),
  }));
}
/** Warnings with no field (NO_MARKER_CANDIDATE) are shown above the table. */
export const generalWarnings = ins => (ins.warnings ?? []).filter(w => !w.field).map(warningText);

export function percent(p) {
  const v = Number(p) * 100;
  if (!Number.isFinite(v)) return '?';
  return `${v < 10 && v > 0 ? v.toFixed(1) : Math.round(v)}%`;
}

export const formatText = f => (f === 'json' ? 'JSON' : f === 'csv' ? 'CSV' : String(f));

/** Rule sentence for the selected markers (threshold = min(2, m)). */
export function thresholdText(markers) {
  const m = markers.length;
  if (m === 0) return 'Select at least 1 marker.';
  const t = Math.min(2, m);
  return `A canary counts as matched when at least ${t} of the ${m} markers (${markers.join(', ')}) are found together in one record of the copy.`;
}

// ---------------------------------------------------------------- input checks (null = ok)
export function passphraseProblem(p, again) {
  if (typeof p !== 'string' || p.length < PASSPHRASE_MIN) return `The passphrase must be at least ${PASSPHRASE_MIN} characters.`;
  if (again !== undefined && p !== again) return 'The two passphrases do not match.';
  return null;
}
export function canaryCountProblem(v) {
  const s = String(v ?? '').trim();
  const n = Number(s);
  if (!/^\d+$/.test(s) || n < CANARY_MIN || n > CANARY_MAX) return `The canary count must be an integer between ${CANARY_MIN} and ${CANARY_MAX}.`;
  return null;
}
export function markerProblem(markers) {
  if (markers.length < 1) return 'Select at least 1 marker field.';
  if (markers.length > MARKER_MAX) return `You can select at most ${MARKER_MAX} marker fields.`;
  return null;
}
export function datasetIdProblem(id) {
  if (typeof id !== 'string' || id.trim() === '') return 'Enter a dataset ID.';
  if (new TextEncoder().encode(id).length > 256) return 'The dataset ID must be at most 256 bytes in UTF-8.';
  return null;
}

/** exclusions file: UTF-8 text, one value per line, empty lines ignored (same as the CLI). */
export function parseExclusions(text) {
  return String(text).replace(/^﻿/, '').split(/\r?\n/).map(s => s.trim()).filter(s => s !== '');
}

// ---------------------------------------------------------------- file names
const stemOf = name => {
  const base = String(name || 'data').split(/[\\/]/).pop();
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(0, i) : base;
};
/** `<stem>.marked.<json|csv>` and `<stem>.evidence.json` (same as `norea protect`). */
export function protectFileNames(inputName, format) {
  const stem = stemOf(inputName);
  const ext = format === 'csv' ? 'csv' : 'json';
  return { marked: `${stem}.marked.${ext}`, evidence: `${stem}.evidence.json`, markedMime: ext === 'csv' ? 'text/csv' : 'application/json' };
}
/** `x.evidence.json` -> `x`; other names lose only the extension. */
export function evidenceStem(evidenceName) {
  return stemOf(evidenceName).replace(/\.evidence$/, '') || 'norea';
}
/** `<stem>.evidence.anchored.json` for the evidence with a time anchor attached. */
export const anchoredName = inputName => `${stemOf(inputName)}.evidence.anchored.json`;
/** Status lines after platform.anchor(): genTime of the newest anchor + the TSA-chain note. */
export function anchoredLines(results, genTime) {
  const lines = [];
  for (const r of Array.isArray(results) ? results : []) {
    lines.push(r.ok ? `Anchored (${r.kind}): genTime ${genTime ?? 'unknown'}` : `Anchor ${r.kind} failed: ${r.error ?? 'unknown error'}`);
  }
  lines.push(TEXT.tsaChain);
  return lines;
}
export const checkReportName = evidenceName => `${evidenceStem(evidenceName)}.check-report.json`;
export const disclosureName = evidenceName => `${evidenceStem(evidenceName)}.disclosure.json`;
export const KEY_BACKUP_NAME = 'norea-key-backup.json';

// ---------------------------------------------------------------- errors
const HINTS = {
  KEY_MISSING: () => "First create a key in the 'Signing key' tab or restore one from a backup.",
  KEY_EXISTS: () => "A signing key already exists. To make a new one, download a backup and then delete the key in the 'Signing key' tab.",
  PRF_UNSUPPORTED: () => 'Create the key with the passphrase fields below.',
  CANCELLED: () => 'Cancelled. You can try again.',
  NO_MARKER: () => 'Pick marker fields (text or number) in the table yourself.',
  CANARY_EXHAUSTED: () => 'Use a release without the fields warned as having no free value space, lower the canary count, or pick different markers.',
  BAD_EVIDENCE: ctx => (ctx === 'verify'
    ? 'The evidence is damaged or was tampered with.'
    : 'Wrong key, or the evidence was tampered with. Check that this evidence was made with this signing key.'),
  BAD_DISCLOSURE: ctx => (ctx === 'verify'
    ? 'The file structure is invalid, so it cannot be verified (same as norea-verify exit code 2).'
    : 'The selected canaries to disclose or the input values are invalid.'),
  ANCHOR_UNAVAILABLE: () => 'No anchor relay is available in this deployment. Use the CLI: norea anchor <evidence.json> --tsa URL.',
  BACKUP_INVALID: () => 'The backup file is damaged or in a format this version cannot open.',
};

/**
 * `{message, hint, detail}` for an Error thrown by platform.js.
 * message = e.message verbatim (platform writes English); hint by e.code; detail for "Details".
 * ctx: 'key' | 'protect' | 'check' | 'disclose' | 'verify'. forcedJson: the operator forced format json.
 * jsonName: auto-detect was used on a file named *.json (so a BAD_INPUT came from the CSV reader).
 */
export function errorView(e, { ctx, forcedJson, jsonName } = {}) {
  const message = String(e?.message || 'An unexpected error occurred during processing.');
  const code = e?.code ?? null;
  let hint = code && HINTS[code] ? HINTS[code](ctx) : null;
  if (code === 'BAD_INPUT' && forcedJson) hint = TEXT.notStandardJson;
  else if (code === 'BAD_INPUT' && jsonName) hint = TEXT.jsonReadAsCsv;
  const detail = typeof e?.detail === 'string' && e.detail ? e.detail : null;
  return { message, hint, detail, code };
}

// ---------------------------------------------------------------- key status
const METHOD_TEXT = { prf: 'passkey(PRF)', passphrase: 'passphrase', 'secure-enclave': 'Secure Enclave', 'tpm-sealed': 'TPM', keystore: 'Android Keystore' };

/** Lines for the key panel. `info` is keyInfo() (or null), `caps` is capabilities(). */
export function keyStatus(caps, info) {
  const lines = [];
  const notes = [];
  if (!info) {
    lines.push('No signing key. Create one below or restore it from a backup file.');
  } else {
    lines.push(`Storage method: ${METHOD_TEXT[info.method] ?? info.method}`);
    lines.push(`Public key fingerprint: ${info.fingerprint}`);
    if (info.createdClaim) lines.push(`Created (claim): ${info.createdClaim}`);
    notes.push(TEXT.createdClaim);
    if (info.method === 'prf') notes.push(TEXT.prfBackup, TEXT.prfSecondBackupMissing);
    if (info.persisted === true) notes.push(TEXT.storageKept);
    else notes.push(TEXT.storageMayClear);
    notes.push(TEXT.keyLoss);
  }
  const hw = info ? info.hardwareDuringSigning : caps?.hardwareDuringSigning;
  const warnings = hw === false ? [TEXT.hardwareMemory, TEXT.hardwareMemoryMore] : [];
  return { lines, notes, warnings };
}

export function prfText(prf) {
  if (prf === true) return TEXT.prfYes;
  if (prf === false) return TEXT.prfNo;
  return TEXT.prfUnknown;
}

// ---------------------------------------------------------------- anchors (both camelCase and snake_case)
/**
 * Anchor section items. Rule (WP-05 memo): `error` -> N/A + error text; else imprint ok -> PASS/FAIL;
 * no anchors -> N/A + "does not prove when it was created"; the TSA-chain sentence is always shown.
 */
export function anchorItems(anchors) {
  const items = [];
  const list = Array.isArray(anchors) ? anchors : [];
  if (list.length === 0) {
    items.push({ status: 'N/A', text: 'No time anchor. This evidence does not prove when it was created.' });
  }
  list.forEach((a, k) => {
    const err = a.error ?? null;
    const imprint = a.imprintOk ?? a.imprint_ok;
    const gen = a.genTime ?? a.gen_time;
    if (err) items.push({ status: 'N/A', text: `anchor ${k} (${a.kind}): not verified. ${err}` });
    else items.push({ status: imprint ? 'PASS' : 'FAIL', text: `anchor ${k} (${a.kind}): imprint ${imprint ? 'match' : 'mismatch'}${gen ? `, genTime ${gen}` : ''}` });
  });
  if (list.length > 0 && list.every(a => a.error)) items.push({ status: 'N/A', text: 'No anchor was verified, so this evidence does not prove when it was created.' });
  items.push({ status: 'NOTE', text: TEXT.tsaChain });
  return items;
}

const pf = b => (b ? 'PASS' : 'FAIL');

// ---------------------------------------------------------------- check report (shape-v1 §7.5)
export function checkView(r) {
  const per = r.per_index ?? {};
  const matched = new Set(r.matched_indices ?? []);
  const partial = new Set(r.partial_indices ?? []);
  const rows = [];
  for (let i = 0; i < r.total; i++) {
    const status = matched.has(i) ? 'matched' : partial.has(i) ? 'partial' : 'absent';
    const p = per[String(i)];
    rows.push({ index: i, status, found: p?.found?.join(', ') ?? '', hint: p?.record_hint ?? '' });
  }
  const ev = r.evidence ?? {};
  return {
    counts: { matched: r.matched, partial: r.partial, absent: r.absent, total: r.total },
    countsText: `Matched ${r.matched} / partial ${r.partial} / absent ${r.absent} (${r.total} canaries in total)`,
    commitOk: r.commit_ok === true,
    commitText: r.commit_ok === true ? null : TEXT.commitBad,
    suspectKind: r.suspect_kind,
    rows,
    evidenceItems: [
      { status: pf(ev.signature_ok), text: 'Signature (ML-DSA-65)' },
      { status: pf(ev.evidence_id_ok), text: 'evidence_id = SHA-256(payload)' },
      { status: pf(ev.blob_hash_ok), text: 'canary blob hash' },
      { status: r.commit_ok ? 'PASS' : 'FAIL', text: 'Open canaries with this signing key and recompute the Merkle root (commit_ok)' },
    ],
    anchorItems: anchorItems(ev.anchors),
    partialNote: r.partial > 0 ? 'Partial: only some markers were found in one record. Not counted as matched, and cannot go into a disclosure package.' : null,
    matchedIndices: [...matched].sort((a, b) => a - b),
  };
}

// ---------------------------------------------------------------- verify (WP-05 human output sections)
/** EvidenceVerification (camelCase) -> sections. PASS = signature && id && blob hash (norea-verify evidence exit 0). */
export function evidenceSections(v) {
  const ok = v.signatureOk && v.evidenceIdOk && v.blobHashOk;
  return {
    pass: !!ok,
    sections: [
      { title: '1. Evidence', items: [
        { status: pf(v.signatureOk), text: 'Signature (ML-DSA-65)' },
        { status: pf(v.evidenceIdOk), text: 'evidence_id = SHA-256(payload)' },
        { status: pf(v.blobHashOk), text: 'canary blob hash' },
      ] },
      { title: '2. Time anchor (a checked anchor with a wrong imprint FAILs; none is fine)', items: anchorItems(v.anchors) },
      { title: '3. Verdict', items: [
        { status: ok ? 'PASS' : 'FAIL', text: `Signature, evidence_id, blob hash -> ${ok ? 'PASS' : 'FAIL'}` },
        { status: 'NOTE', text: TEXT.evidenceOnly },
      ] },
    ],
    statement: null,
  };
}

/** norea.disclosure-report.v1 -> sections. PASS = verdict.integrity_ok && verdict.all_reproduced (disclosure-v1 §4). */
export function disclosureSections(r) {
  const ev = r.evidence ?? {};
  const s = r.summary ?? {};
  const v = r.verdict ?? {};
  const pass = v.integrity_ok === true && v.all_reproduced === true;
  const perItem = (r.disclosed ?? []).map(d => ({
    status: d.merkle_ok && d.matched ? 'PASS' : 'FAIL',
    text: `index ${d.index}: merkle ${pf(d.merkle_ok)}, reproduced ${d.matched ? 'PASS' : 'NOT REPRODUCED'}${d.found?.length ? `, found [${d.found.join(', ')}]` : ''}`,
  }));
  return {
    pass,
    sections: [
      { title: '1. Evidence', items: [
        { status: pf(ev.signature_ok), text: 'Signature (ML-DSA-65)' },
        { status: pf(ev.evidence_id_ok), text: 'evidence_id = SHA-256(payload)' },
        { status: pf(ev.blob_hash_ok), text: 'canary blob hash' },
      ] },
      { title: '2. Time anchor (a checked anchor with a wrong imprint FAILs; none is fine)', items: anchorItems(ev.anchors) },
      { title: '3. Copy', items: [
        { status: pf(r.suspect_hash_ok), text: 'Copy SHA-256 = suspect.sha256 in the disclosure' },
        { status: 'NOTE', text: TEXT.noCaptureProof },
      ] },
      { title: '4. Disclosed canaries', items: [
        { status: s.disclosed >= 1 && s.merkle_ok === s.disclosed ? 'PASS' : 'FAIL', text: `Merkle path -> signed canary_root: ${s.merkle_ok}/${s.disclosed}` },
        { status: s.not_reproduced === 0 && s.disclosed >= 1 ? 'PASS' : 'FAIL', text: `Reproduced in the copy: ${s.matched}/${s.disclosed}` },
        ...perItem,
      ] },
      { title: '5. Verdict', items: [
        { status: pass ? 'PASS' : 'FAIL', text: `integrity_ok: ${v.integrity_ok}, all_reproduced: ${v.all_reproduced} -> ${pass ? 'PASS' : 'FAIL'}` },
      ] },
    ],
    statementTitle: '6. Statement (verbatim from the verifier)',
    statement: typeof r.statement === 'string' ? r.statement : '',
  };
}

/** Which document is this? 'evidence' | 'disclosure' | null (not JSON or unknown schema). */
export function docKind(text) {
  try {
    const s = JSON.parse(text)?.schema;
    if (s === 'norea.evidence.v1') return 'evidence';
    if (s === 'norea.disclosure.v1') return 'disclosure';
  } catch { /* fall through */ }
  return null;
}
