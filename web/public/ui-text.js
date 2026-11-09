// Pure UI text and view-model helpers for app.js (WP-07).
// No imports, no DOM, no platform calls: everything here turns contract results
// (platform-contract v1 types) into Korean sentences and plain data that app.js renders.
// tests/ui.node.mjs unit-tests this module in node.
//
// Rules (WP-07 spec): no emoji; technical terms stay English (canary, evidence, anchor,
// passkey, marker); what is not verified is written as "증명하지 않습니다".

export const PASSPHRASE_MIN = 12;
export const CANARY_MIN = 8;
export const CANARY_MAX = 256;
export const CANARY_DEFAULT = 32;
export const MARKER_MAX = 4;

// ---------------------------------------------------------------- fixed sentences
export const TEXT = {
  hardwareMemory: '서명하는 동안 키가 이 브라우저 메모리에 있습니다.',
  hardwareMemoryMore: '키는 하드웨어 보안 장치 안에서 서명되지 않습니다. 더 높은 보증이 필요하면 데스크톱 앱(준비 중)을 쓰세요.',
  storageMayClear: '브라우저가 키 저장소를 지울 수 있습니다. 백업 파일을 안전한 곳에 따로 보관하세요.',
  storageKept: '이 브라우저는 키 저장소를 유지하겠다고 응답했습니다. 그래도 백업 파일은 따로 보관하세요.',
  prfBackup: 'passkey를 잃으면 이 백업도 열 수 없습니다. passkey로 만든 백업은 같은 passkey가 있는 기기에서만 열립니다.',
  prfSecondBackupMissing: 'passphrase로 감싼 두 번째 백업을 만드는 기능은 아직 없습니다. passkey를 잃을 위험이 걱정되면 passphrase 방식으로 키를 만드세요.',
  keyLoss: '서명키를 잃으면 기존 evidence의 canary를 복원할 수 없어, 그 발행본에 대해 대조와 공개 패키지를 만들 수 없습니다.',
  backupForced: '키를 만들면 암호화된 백업 파일(norea-key-backup.json)이 바로 내려받아집니다. 이 파일만으로는 키를 열 수 없고, passphrase 또는 passkey가 함께 있어야 합니다.',
  passphraseRule: `passphrase는 ${PASSPHRASE_MIN}자 이상이어야 합니다. 어디에도 보내지 않으며, 잊으면 아무도 복구할 수 없습니다.`,
  passphraseMemory: '입력한 passphrase는 사용 직후 입력란에서 지웁니다. 다만 브라우저가 문자열을 메모리에서 즉시 지우는 것은 보장하지 못합니다.',
  createdClaim: '생성 시각은 이 기기 시계의 주장일 뿐이며 시점을 증명하지 않습니다.',
  prfUnknown: '이 브라우저가 passkey(PRF)를 지원하는지 미리 알 수 없습니다. passkey로 시도해 보고, 안 되면 passphrase로 만드세요. 시도가 실패하면 방금 만든 passkey가 쓰이지 않은 채 기기에 남을 수 있습니다.',
  prfNo: '이 브라우저에서는 passkey(PRF)를 쓸 수 없습니다. passphrase로 만드세요.',
  prfYes: '이 브라우저는 passkey(PRF)를 지원합니다.',
  jsonReserialize: 'JSON 입력은 canary를 넣으며 파일 전체를 다시 씁니다. 값은 그대로지만 들여쓰기와 공백 같은 출력 파일 형식이 바뀔 수 있습니다.',
  notStandardJson: '표준 JSON이 아닙니다(주석, 마지막 쉼표 등). 주석과 마지막 쉼표를 지운 뒤 다시 시도하세요.',
  jsonReadAsCsv: "파일 이름은 .json이지만 JSON으로 읽히지 않아 CSV로 읽었습니다. 위 '입력 형식'을 'JSON으로 읽기'로 바꾸면 어디가 문제인지(줄, 열) 알려 줍니다.",
  jsonNameButCsv: '파일 이름은 .json인데 CSV로 감지되었습니다. 주석이나 마지막 쉼표가 있는 JSON일 수 있습니다. 표준 JSON으로 고친 뒤 다시 고르세요.',
  evidencePrivate: 'evidence 파일은 공개하지 마세요. 공개하는 것은 marked 파일뿐입니다. evidence가 있어야 나중에 대조와 공개 패키지를 만들 수 있고, 잃으면 이 발행본의 복제를 증명할 수 없습니다.',
  anchorPending: '시점 anchor는 준비 중입니다.',
  noTimeProof: '현재 이 증거는 생성 시점을 증명하지 않습니다.',
  noCaptureProof: '사본을 언제 어디서 얻었는지(포착 시점)는 이 제품이 증명하지 않습니다. 공증, 웹 아카이브 같은 외부 증거로 보강하세요.',
  tsaChain: 'TSA 인증서 체인은 이 도구가 검증하지 않습니다(chain_verified: false). 체인 확인은 norea-verify --export-anchors 후 openssl ts -verify로 직접 합니다.',
  commitBad: '이 증거는 이 서명키로 만든 것이 아니거나 변조되었습니다. 그래서 대조하지 않았습니다(일치 0).',
  discloseBefore: '공개하는 canary는 상대방이 알게 되어 다음 사본에서 제거될 수 있습니다. 일치한 canary만 공개하고, 전체 canary의 일부만 공개하는 것을 권합니다.',
  discloseNoSecret: '이 파일에는 마스터 키나 서명키가 들어 있지 않습니다. 공개되지 않은 canary는 암호화된 상태로만 포함됩니다.',
  discloseClaim: '아래 세 칸은 운영자의 주장(claim)으로 기록되며 검증되지 않습니다.',
  discloseSubmit: '공개 패키지는 대조에 쓴 사본 파일과 함께 제출하세요. 검증하는 쪽은 두 파일이 모두 있어야 합니다.',
  verifyNoKey: '이 탭은 서명키 없이 동작합니다. 누구나 evidence 또는 공개 패키지(disclosure)를 검증할 수 있고, 파일은 이 브라우저 밖으로 나가지 않습니다.',
  evidenceOnly: 'evidence만 검증하면 서명과 해시만 확인합니다. 사본과의 일치는 공개 패키지와 사본 파일로 검증하세요.',
  limits: [
    '데이터를 통째로 바꾼 사본은 canary로 잡지 못합니다.',
    'canary가 실제로 존재하지 않는 값이라는 보장은 exclusions 파일(공식 목록)을 넣을 때만 완전합니다.',
    '날짜 형식 필드에서는 존재하지 않는 날짜(예: 2월 31일)가 만들어질 수 있습니다.',
    '생성기는 필드 사이의 관계(예: 주소의 시와 별도 시도명 열)를 모릅니다. 관계가 강한 데이터에서는 통계적으로 걸러질 수 있습니다.',
    '행마다 다른 자유 텍스트 필드는 canary에 실제 값이 복사되어 중복으로 드러날 수 있습니다.',
  ],
};

// ---------------------------------------------------------------- inspect warnings (shape-v1 §6.2)
const q = f => (f ? `'${f}' 필드` : '이 필드');

/** One Korean sentence per inspect warning code (canary-record-shape-v1 §6.2, §8). */
export function warningText({ code, field } = {}) {
  switch (code) {
    case 'OPAQUE_FIELD':
      return `${q(field)}는 값의 모양이 제각각이라 새 값을 만들 수 없어, canary에 실제 값이 그대로 복사됩니다. marker로 쓸 수 없습니다.`;
    case 'UNIQUE_OPAQUE_COPIED':
      return `${q(field)}는 행마다 다른 자유 텍스트라서, canary에 복사된 값이 원본의 다른 행과 똑같이 겹칩니다. 이 중복으로 canary가 드러날 수 있으니 이 필드를 뺀 발행본을 권합니다.`;
    case 'LOW_FREE_SPACE':
      return `${q(field)}는 만들 수 있는 값의 절반 이상이 이미 실제 값이라 marker로 적합하지 않습니다.`;
    case 'NO_FREE_SPACE':
      return `${q(field)}는 빈 값 공간이 없어 canary를 만들 수 없습니다(연번처럼 값이 빈틈없이 채워진 필드). 이대로 보호하면 실패할 가능성이 매우 높습니다. 이 필드를 뺀 발행본을 만드세요.`;
    case 'HIGH_MISSING':
      return `${q(field)}는 값이 비어 있는 행이 20% 이상이라 marker 후보에서 뺐습니다.`;
    case 'NO_MARKER_CANDIDATE':
      return '자동으로 고를 수 있는 marker 후보가 없습니다. 표에서 marker 필드를 직접 고르거나, 값이 다양한 필드가 있는 발행본을 쓰세요.';
    case 'NUMERIC_CODE_LIKE':
      return `${q(field)}는 자릿수가 모두 같은 고유 정수라 코드(우편번호, 법정동코드 등)로 보입니다. 생성기는 코드의 자릿수 구조를 모르므로 canary 값이 통계적으로 구별될 수 있습니다(현재 버전의 한계).`;
    default:
      return `알 수 없는 경고입니다(${String(code)}${field ? `, ${field}` : ''}).`;
  }
}

export const KIND_TEXT = {
  STRING: '문자열', NUMERIC: '숫자', CATEGORICAL: '범주', BOOL: '참/거짓', OPAQUE: '복사(형식 제각각)', EMPTY: '비어 있음',
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
    unique: f.unique ? '예' : '아니오',
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
  if (m === 0) return 'marker를 1개 이상 고르세요.';
  const t = Math.min(2, m);
  return `marker ${m}개(${markers.join(', ')}) 중 ${t}개 이상이 사본의 한 레코드에서 함께 발견되면 그 canary를 일치로 봅니다.`;
}

// ---------------------------------------------------------------- input checks (null = ok)
export function passphraseProblem(p, again) {
  if (typeof p !== 'string' || p.length < PASSPHRASE_MIN) return `passphrase는 ${PASSPHRASE_MIN}자 이상이어야 합니다.`;
  if (again !== undefined && p !== again) return '두 passphrase가 같지 않습니다.';
  return null;
}
export function canaryCountProblem(v) {
  const s = String(v ?? '').trim();
  const n = Number(s);
  if (!/^\d+$/.test(s) || n < CANARY_MIN || n > CANARY_MAX) return `canary 수는 ${CANARY_MIN}~${CANARY_MAX} 사이의 정수여야 합니다.`;
  return null;
}
export function markerProblem(markers) {
  if (markers.length < 1) return 'marker 필드를 1개 이상 고르세요.';
  if (markers.length > MARKER_MAX) return `marker 필드는 최대 ${MARKER_MAX}개까지 고를 수 있습니다.`;
  return null;
}
export function datasetIdProblem(id) {
  if (typeof id !== 'string' || id.trim() === '') return '데이터셋 ID를 입력하세요.';
  if (new TextEncoder().encode(id).length > 256) return '데이터셋 ID는 UTF-8 256바이트 이하여야 합니다.';
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
export const checkReportName = evidenceName => `${evidenceStem(evidenceName)}.check-report.json`;
export const disclosureName = evidenceName => `${evidenceStem(evidenceName)}.disclosure.json`;
export const KEY_BACKUP_NAME = 'norea-key-backup.json';

// ---------------------------------------------------------------- errors
const HINTS = {
  KEY_MISSING: () => "먼저 '서명키' 탭에서 키를 만들거나 백업에서 복원하세요.",
  KEY_EXISTS: () => "이미 서명키가 있습니다. 새로 만들려면 백업을 받은 뒤 '서명키' 탭에서 삭제하세요.",
  PRF_UNSUPPORTED: () => '아래 passphrase 칸으로 키를 만드세요.',
  CANCELLED: () => '취소되었습니다. 다시 시도할 수 있습니다.',
  NO_MARKER: () => '표에서 marker 필드(문자열 또는 숫자)를 직접 고르세요.',
  CANARY_EXHAUSTED: () => '빈 값 공간이 없다는 경고가 있는 필드를 뺀 발행본을 쓰거나, canary 수를 줄이거나, 다른 marker를 고르세요.',
  BAD_EVIDENCE: ctx => (ctx === 'verify'
    ? 'evidence가 손상되었거나 변조되었습니다.'
    : '키가 다르거나 증거가 변조되었습니다. 이 서명키로 만든 evidence인지 확인하세요.'),
  BAD_DISCLOSURE: ctx => (ctx === 'verify'
    ? '파일 구조가 올바르지 않아 검증할 수 없습니다(norea-verify 종료 코드 2에 해당).'
    : '공개할 canary 선택이나 입력값이 올바르지 않습니다.'),
  ANCHOR_UNAVAILABLE: () => '시점 anchor는 다음 버전에서 제공합니다.',
  BACKUP_INVALID: () => '백업 파일이 손상되었거나 이 버전이 열 수 없는 형식입니다.',
};

/**
 * `{message, hint, detail}` for an Error thrown by platform.js.
 * message = e.message verbatim (platform writes Korean); hint by e.code; detail for "자세히".
 * ctx: 'key' | 'protect' | 'check' | 'disclose' | 'verify'. forcedJson: the operator forced format json.
 * jsonName: auto-detect was used on a file named *.json (so a BAD_INPUT came from the CSV reader).
 */
export function errorView(e, { ctx, forcedJson, jsonName } = {}) {
  const message = String(e?.message || '처리 중 예상하지 못한 오류가 발생했습니다.');
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
    lines.push('서명키가 없습니다. 아래에서 만들거나 백업 파일에서 복원하세요.');
  } else {
    lines.push(`보관 방식: ${METHOD_TEXT[info.method] ?? info.method}`);
    lines.push(`공개키 지문: ${info.fingerprint}`);
    if (info.createdClaim) lines.push(`생성 시각(주장): ${info.createdClaim}`);
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
 * no anchors -> N/A + "생성 시점을 증명하지 않습니다"; the TSA-chain sentence is always shown.
 */
export function anchorItems(anchors) {
  const items = [];
  const list = Array.isArray(anchors) ? anchors : [];
  if (list.length === 0) {
    items.push({ status: 'N/A', text: '시점 anchor 없음. 이 증거는 생성 시점을 증명하지 않습니다.' });
  }
  list.forEach((a, k) => {
    const err = a.error ?? null;
    const imprint = a.imprintOk ?? a.imprint_ok;
    const gen = a.genTime ?? a.gen_time;
    if (err) items.push({ status: 'N/A', text: `anchor ${k} (${a.kind}): 검증하지 않음. ${err}` });
    else items.push({ status: imprint ? 'PASS' : 'FAIL', text: `anchor ${k} (${a.kind}): imprint ${imprint ? '일치' : '불일치'}${gen ? `, genTime ${gen}` : ''}` });
  });
  if (list.length > 0 && list.every(a => a.error)) items.push({ status: 'N/A', text: '검증한 anchor가 없으므로 이 증거는 생성 시점을 증명하지 않습니다.' });
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
    const status = matched.has(i) ? '일치' : partial.has(i) ? '부분' : '없음';
    const p = per[String(i)];
    rows.push({ index: i, status, found: p?.found?.join(', ') ?? '', hint: p?.record_hint ?? '' });
  }
  const ev = r.evidence ?? {};
  return {
    counts: { matched: r.matched, partial: r.partial, absent: r.absent, total: r.total },
    countsText: `일치 ${r.matched} / 부분 ${r.partial} / 없음 ${r.absent} (전체 canary ${r.total}개)`,
    commitOk: r.commit_ok === true,
    commitText: r.commit_ok === true ? null : TEXT.commitBad,
    suspectKind: r.suspect_kind,
    rows,
    evidenceItems: [
      { status: pf(ev.signature_ok), text: '서명 (ML-DSA-65)' },
      { status: pf(ev.evidence_id_ok), text: 'evidence_id = SHA-256(payload)' },
      { status: pf(ev.blob_hash_ok), text: 'canary blob 해시' },
      { status: r.commit_ok ? 'PASS' : 'FAIL', text: '이 서명키로 canary를 열고 Merkle root 재계산(commit_ok)' },
    ],
    anchorItems: anchorItems(ev.anchors),
    partialNote: r.partial > 0 ? '부분: marker 일부만 한 레코드에서 발견되었습니다. 일치로 세지 않으며 공개 패키지에 넣을 수 없습니다.' : null,
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
        { status: pf(v.signatureOk), text: '서명 (ML-DSA-65)' },
        { status: pf(v.evidenceIdOk), text: 'evidence_id = SHA-256(payload)' },
        { status: pf(v.blobHashOk), text: 'canary blob 해시' },
      ] },
      { title: '2. 시점 anchor (판정에 넣지 않음)', items: anchorItems(v.anchors) },
      { title: '3. 판정', items: [
        { status: ok ? 'PASS' : 'FAIL', text: `서명, evidence_id, blob 해시 -> ${ok ? 'PASS' : 'FAIL'}` },
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
    text: `index ${d.index}: merkle ${pf(d.merkle_ok)}, 재현 ${d.matched ? 'PASS' : 'NOT REPRODUCED'}${d.found?.length ? `, 발견 [${d.found.join(', ')}]` : ''}`,
  }));
  return {
    pass,
    sections: [
      { title: '1. Evidence', items: [
        { status: pf(ev.signature_ok), text: '서명 (ML-DSA-65)' },
        { status: pf(ev.evidence_id_ok), text: 'evidence_id = SHA-256(payload)' },
        { status: pf(ev.blob_hash_ok), text: 'canary blob 해시' },
      ] },
      { title: '2. 시점 anchor (판정에 넣지 않음)', items: anchorItems(ev.anchors) },
      { title: '3. 사본', items: [
        { status: pf(r.suspect_hash_ok), text: '사본 SHA-256 = disclosure의 suspect.sha256' },
        { status: 'NOTE', text: TEXT.noCaptureProof },
      ] },
      { title: '4. 공개된 canary', items: [
        { status: s.disclosed >= 1 && s.merkle_ok === s.disclosed ? 'PASS' : 'FAIL', text: `Merkle path -> 서명된 canary_root: ${s.merkle_ok}/${s.disclosed}` },
        { status: s.not_reproduced === 0 && s.disclosed >= 1 ? 'PASS' : 'FAIL', text: `사본에서 재현: ${s.matched}/${s.disclosed}` },
        ...perItem,
      ] },
      { title: '5. 판정', items: [
        { status: pass ? 'PASS' : 'FAIL', text: `integrity_ok: ${v.integrity_ok}, all_reproduced: ${v.all_reproduced} -> ${pass ? 'PASS' : 'FAIL'}` },
      ] },
    ],
    statementTitle: '6. Statement (verifier가 만든 원문 그대로)',
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
