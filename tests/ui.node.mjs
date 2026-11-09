// Unit tests for web/public/ui-text.js (WP-07): the pure text and view helpers app.js renders.
// app.js itself needs a DOM and is exercised in a real browser (WP-09); this file covers
// every sentence rule and result -> section mapping that does not need one.
// Part 2 feeds REAL platform results (passphrase path, node + fake-indexeddb) through the
// helpers, so a contract shape change shows up here.
//
// Run: node tests/ui.node.mjs <abs dir holding ui-text.js, platform.js, platform-web.js, custody.js and pkg/>
import 'fake-indexeddb/auto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const realFetch = globalThis.fetch;
globalThis.fetch = async u => {
  const url = new URL(u);
  if (url.protocol === 'file:') return new Response(await readFile(url), { headers: { 'Content-Type': 'application/wasm' } });
  return realFetch(u);
};
globalThis.window = globalThis;

let passed = 0;
const ok = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } passed++; console.log('ok  ', m); };
const root = process.argv[2];
const T = await import(pathToFileURL(`${root}/ui-text.js`).href);
const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;
// English sentence: has Latin letters and no Hangul syllables (U+AC00..U+D7A3).
const ENGLISH = s => /[A-Za-z]/.test(s) && !/[\uAC00-\uD7A3]/.test(s);

// ---------------------------------------------------------------- 1. module surface
{
  const src = await readFile(`${root}/ui-text.js`, 'utf8');
  ok(!/^\s*import\b/m.test(src) && !/import\s*\(/.test(src), 'ui-text.js imports nothing (pure)');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  ok(!/\bdocument\.|\bwindow\.|\bplatform\b|indexedDB|crypto\.subtle|localStorage|console\./.test(code), 'ui-text.js touches no DOM, platform, storage or console (comments excluded)');
}

// ---------------------------------------------------------------- 2. warning codes (shape-v1 §6.2)
const CODES = ['OPAQUE_FIELD', 'UNIQUE_OPAQUE_COPIED', 'LOW_FREE_SPACE', 'NO_FREE_SPACE', 'HIGH_MISSING', 'NO_MARKER_CANDIDATE', 'NUMERIC_CODE_LIKE'];
const seen = new Set();
for (const code of CODES) {
  const field = code === 'NO_MARKER_CANDIDATE' ? undefined : 'seq';
  const s = T.warningText({ code, field });
  ok(ENGLISH(s) && !EMOJI.test(s) && !s.startsWith('Unknown'), `${code} -> English sentence: ${s}`);
  if (field) ok(s.includes("Field 'seq'"), `${code} names the field`);
  ok(!seen.has(s), `${code} sentence is distinct`);
  seen.add(s);
}
ok(T.warningText({ code: 'NO_FREE_SPACE', field: 'seq' }).includes('Make a release without this field'), 'NO_FREE_SPACE tells the action (drop the field)');
ok(T.warningText({ code: 'NO_FREE_SPACE', field: 'seq' }).includes('has no free value space, so canaries cannot be generated'), 'NO_FREE_SPACE says canary cannot be made');
ok(T.warningText({ code: 'UNIQUE_OPAQUE_COPIED', field: 'f' }).includes('a release without this field'), 'UNIQUE_OPAQUE_COPIED recommends excluding (§8 limit 4)');
ok(T.warningText({ code: 'NUMERIC_CODE_LIKE', field: 'f' }).includes('limitation'), 'NUMERIC_CODE_LIKE states the limit (§3.1, §8)');
ok(T.warningText({ code: 'HIGH_MISSING', field: 'f' }).includes('20%'), 'HIGH_MISSING mentions 20%');
ok(T.warningText({ code: 'ZZZ' }).startsWith('Unknown warning'), 'unknown code -> generic sentence, no throw');

// ---------------------------------------------------------------- 3. input checks
ok(T.passphraseProblem('12345678901') !== null, 'passphrase of 11 chars rejected');
ok(T.passphraseProblem('123456789012') === null, 'passphrase of 12 chars accepted');
ok(T.passphraseProblem('123456789012', '123456789013') !== null, 'mismatched confirmation rejected');
ok(T.passphraseProblem(undefined) !== null, 'missing passphrase rejected');
for (const [v, good] of [['8', true], ['256', true], ['32', true], ['7', false], ['257', false], ['3.5', false], ['', false], ['abc', false], ['-8', false]]) {
  ok((T.canaryCountProblem(v) === null) === good, `canary count ${JSON.stringify(v)} -> ${good ? 'ok' : 'rejected'}`);
}
ok(T.markerProblem([]) !== null && T.markerProblem(['a', 'b', 'c', 'd', 'e']) !== null && T.markerProblem(['a']) === null, 'markers: 1..4');
ok(T.datasetIdProblem('  ') !== null && T.datasetIdProblem('a/b') === null && T.datasetIdProblem('가'.repeat(86)) !== null, 'dataset id: non-empty, <= 256 UTF-8 bytes');
ok(JSON.stringify(T.parseExclusions('﻿a\r\n\n b \nc')) === '["a","b","c"]', 'exclusions: one per line, trimmed, empty lines dropped, BOM removed');
ok(T.thresholdText(['a']).includes('at least 1 of the 1') && T.thresholdText(['a', 'b', 'c']).includes('at least 2 of the 3'), 'threshold sentence uses min(2, m)');

// ---------------------------------------------------------------- 4. file names
{
  const n = T.protectFileNames('parcels.json', 'json');
  ok(n.marked === 'parcels.marked.json' && n.evidence === 'parcels.evidence.json' && n.markedMime === 'application/json', 'json names <stem>.marked.json / <stem>.evidence.json');
  const c = T.protectFileNames('dir/표.v2.csv', 'csv');
  ok(c.marked === '표.v2.marked.csv' && c.evidence === '표.v2.evidence.json' && c.markedMime === 'text/csv', 'csv names keep inner dots, drop path');
  ok(T.checkReportName('parcels.evidence.json') === 'parcels.check-report.json' && T.disclosureName('parcels.evidence.json') === 'parcels.disclosure.json', 'report / disclosure names from evidence name');
  ok(T.KEY_BACKUP_NAME === 'norea-key-backup.json', 'key backup name');
}

// ---------------------------------------------------------------- 5. errors
{
  const mk = (code, message, detail) => Object.assign(new Error(message), { code, detail });
  const v = T.errorView(mk('BAD_INPUT', 'The input file or options are invalid.', 'BadInput: invalid JSON at line 1 column 9'), { ctx: 'protect', forcedJson: true });
  ok(v.message === 'The input file or options are invalid.' && v.hint.startsWith('Not standard JSON (comments, trailing commas, etc.)') && v.detail.includes('line 1 column 9'),
    'forced JSON + BAD_INPUT -> message verbatim, "Not standard JSON" hint, detail with line/column');
  ok(T.errorView(mk('BAD_INPUT', 'x'), { ctx: 'protect', forcedJson: false }).hint === null, 'BAD_INPUT without forced JSON -> no JSON hint');
  ok(T.errorView(mk('BAD_INPUT', 'x'), { ctx: 'protect', jsonName: true }).hint === T.TEXT.jsonReadAsCsv, 'auto-detect on *.json + BAD_INPUT -> "Read as JSON" hint');
  ok(T.errorView(mk('BAD_INPUT', 'x'), { ctx: 'protect', forcedJson: true, jsonName: true }).hint === T.TEXT.notStandardJson, 'forced JSON wins over the file-name hint');
  ok(T.errorView(mk('BAD_EVIDENCE', 'x'), { ctx: 'check' }).hint.includes('Wrong key, or the evidence was tampered with'), 'BAD_EVIDENCE in check -> "Wrong key, or the evidence was tampered with"');
  ok(!/key/i.test(T.errorView(mk('BAD_EVIDENCE', 'x'), { ctx: 'verify' }).hint), 'BAD_EVIDENCE in verify does not mention a key');
  for (const code of ['KEY_MISSING', 'KEY_EXISTS', 'PRF_UNSUPPORTED', 'CANCELLED', 'NO_MARKER', 'CANARY_EXHAUSTED', 'BAD_DISCLOSURE', 'ANCHOR_UNAVAILABLE', 'BACKUP_INVALID']) {
    const h = T.errorView(mk(code, 'm')).hint;
    ok(typeof h === 'string' && ENGLISH(h), `${code} -> hint ${h}`);
  }
  ok(T.errorView(mk('BAD_PASSPHRASE', 'Cannot unlock the key.')).hint === null, 'BAD_PASSPHRASE: platform message alone');
  const plain = T.errorView(new Error('An unexpected error occurred during processing.'));
  ok(plain.code === null && plain.detail === null && plain.hint === null, 'error without code -> message only');
  ok(T.errorView(undefined).message.length > 0, 'non-Error -> generic message');
}

// ---------------------------------------------------------------- 6. key status, hardware honesty
{
  const caps = { platform: 'web', prf: 'unknown', hardwareDuringSigning: false, anchorRelay: null };
  const none = T.keyStatus(caps, null);
  ok(none.warnings.includes('During signing, the key is in this browser\'s memory.'), 'no key, hardwareDuringSigning false -> memory sentence');
  const pass = T.keyStatus(caps, { method: 'passphrase', fingerprint: '0123456789abcdef', hardwareDuringSigning: false, createdClaim: '2026-11-09T00:00:00Z', persisted: 'unknown' });
  ok(pass.warnings.includes(T.TEXT.hardwareMemory) && pass.lines.some(l => l.includes('0123456789abcdef')), 'passphrase key: fingerprint and memory sentence');
  ok(pass.notes.includes(T.TEXT.storageMayClear), 'persisted "unknown" -> storage may be cleared');
  ok(T.keyStatus(caps, { method: 'passphrase', fingerprint: 'f', hardwareDuringSigning: false, persisted: false }).notes.includes(T.TEXT.storageMayClear), 'persisted false -> storage may be cleared');
  ok(!T.keyStatus(caps, { method: 'passphrase', fingerprint: 'f', hardwareDuringSigning: false, persisted: true }).notes.includes(T.TEXT.storageMayClear), 'persisted true -> no clear warning');
  const prf = T.keyStatus(caps, { method: 'prf', fingerprint: 'f', hardwareDuringSigning: false, persisted: true });
  ok(prf.notes.includes(T.TEXT.prfBackup) && T.TEXT.prfBackup.startsWith('If you lose the passkey, this backup cannot be opened'), 'prf key -> "If you lose the passkey, this backup cannot be opened"');
  ok(pass.notes.includes(T.TEXT.createdClaim), 'createdClaim is a claim, not time proof');
  const hw = T.keyStatus({ ...caps, hardwareDuringSigning: true }, { method: 'secure-enclave', fingerprint: 'f', hardwareDuringSigning: true, persisted: true });
  ok(hw.warnings.length === 0, 'hardwareDuringSigning true -> no memory sentence (and never a "never leaves hardware" claim here)');
  ok(T.prfText('unknown') === T.TEXT.prfUnknown && T.prfText(false) === T.TEXT.prfNo && T.prfText(true) === T.TEXT.prfYes, 'prf 3 states');
}
{
  // Preview build: banner is static in index.html (ui-text.js may not say "custody"); passkey option hidden, passphrase stays.
  const html = await readFile(new URL('../web/public/index.html', import.meta.url), 'utf8');
  const banner = 'Preview build. Try it with sample data, not with keys you care about. Passkey custody and non-Chromium browsers are not yet tested; use a passphrase.';
  ok(html.includes(`<p id="preview-banner" class="preview-banner" role="note">${banner}</p>`), 'preview banner present in index.html');
  ok(/<div id="key-passkey-option"[^>]*\shidden>/.test(html) && html.includes('id="key-create-pass"'), 'preview: passkey option hidden, passphrase option visible');
}

// ---------------------------------------------------------------- 7. anchors
{
  const none = T.anchorItems([]);
  ok(none[0].status === 'N/A' && none[0].text.includes('does not prove when it was created') && none.at(-1).text === T.TEXT.tsaChain, 'no anchors -> N/A "does not prove" + TSA chain note');
  const errd = T.anchorItems([{ kind: 'rfc3161', imprintOk: false, chainVerified: false, error: 'anchor verification not implemented' }]);
  ok(errd[0].status === 'N/A' && errd[0].text.includes('not implemented') && errd.some(i => i.text.includes('does not prove')), 'anchor with error -> N/A');
  const good = T.anchorItems([{ kind: 'rfc3161', imprint_ok: true, gen_time: '2026-11-08T12:00:03Z', chain_verified: false, error: null }]);
  ok(good[0].status === 'PASS' && good[0].text.includes('2026-11-08T12:00:03Z') && good.at(-1).text === T.TEXT.tsaChain, 'verified anchor (snake_case) -> PASS with genTime, chain note still shown');
  ok(T.anchorItems([{ kind: 'ots', imprintOk: false, error: null }])[0].status === 'FAIL', 'imprint mismatch -> FAIL');
}

// ---------------------------------------------------------------- 8. sentences: no emoji, "does not prove"
{
  const all = [...Object.values(T.TEXT).flat()];
  ok(all.every(s => typeof s === 'string' && !EMOJI.test(s)), 'no emoji in fixed sentences');
  ok(T.TEXT.noTimeProof === 'This evidence does not prove when it was created.', 'anchor pending sentence (spec)');
  ok(T.TEXT.noCaptureProof.includes('does not prove') && T.TEXT.noCaptureProof.includes('The source and capture time of the copy are claims and are not verified.') && T.TEXT.tsaChain.startsWith('The TSA certificate chain is not verified by this tool'), 'capture time and TSA chain are stated as not proven');
  ok(T.TEXT.discloseBefore.startsWith('Disclosed canaries become known to the other party') && T.TEXT.discloseNoSecret.startsWith('This file contains neither the master key nor the signing key'), 'disclosure-v1 §6 sentences verbatim');
  ok(T.TEXT.commitBad.startsWith('This evidence was not made with this signing key, or it was tampered with'), 'commit_ok false sentence');
  ok(T.TEXT.verifyNoKey.includes('works without a signing key'), 'verify tab works without a key');
}

// ---------------------------------------------------------------- 9. real platform results through the helpers
const te = new TextEncoder();
const platform = await import(pathToFileURL(`${root}/platform.js`).href);
await platform.ready();
const PW = 'ui test passphrase 2026';
const si = ['하남시 미사동', '성남시 정자동', '용인시 죽전동'];
const rows = [];
for (let i = 0; i < 300; i++) rows.push({ id: `P-${String(i * 3).padStart(6, '0')}`, addr: `${si[i % 3]} ${1 + (i * 7) % 997}-${1 + i % 37}`, area_m2: 50 + (i * 13) % 1950 + (i % 100) / 100, use: ['대', '전'][i % 2], seq: i + 1 });
const input = te.encode(JSON.stringify(rows, null, 2));

const ins = await platform.inspect({ input });
const irows = T.inspectRows(ins);
ok(irows.length === ins.fields.length && irows.filter(r => r.checked).map(r => r.name).sort().join() === [...ins.suggestedMarkers].sort().join(), `inspect rows: suggested markers pre-checked (${ins.suggestedMarkers})`);
ok(irows.find(r => r.name === 'use').eligible === false, 'CATEGORICAL field is not marker-eligible');
const seqRow = irows.find(r => r.name === 'seq');
ok(seqRow.warnings.some(w => w.includes('has no free value space')), 'dense seq field -> NO_FREE_SPACE sentence in its row');

const caps = await platform.capabilities();
await platform.setupKey({ passphrase: PW });
const info = await platform.keyInfo();
ok(T.keyStatus(caps, info).warnings.includes(T.TEXT.hardwareMemory), 'real keyInfo (web) -> memory sentence');

const noSeq = te.encode(JSON.stringify(rows.map(({ seq, ...r }) => r), null, 2));
const pr = await platform.protect({ input: noSeq, datasetId: 'ui/test', n: 8, passphrase: PW, markerFields: (await platform.inspect({ input: noSeq })).suggestedMarkers });
const names = T.protectFileNames('parcels.json', pr.summary.format);
ok(names.marked === 'parcels.marked.json', 'protect summary.format -> file names');

const rep = await platform.check({ suspect: pr.marked, evidenceJson: pr.evidenceJson, passphrase: PW });
const cv = T.checkView(rep);
ok(cv.commitOk && cv.counts.matched === 8 && cv.rows.length === 8 && cv.rows.every(r => r.status === 'matched' && r.found && r.hint), 'checkView: 8 matched rows with found + hint');
ok(cv.evidenceItems.every(i => i.status === 'PASS') && cv.anchorItems[0].status === 'N/A', 'checkView: evidence PASS, anchor N/A');
ok(cv.matchedIndices.join() === '0,1,2,3,4,5,6,7', 'checkView: matched indices for the disclose tab');
const unrelated = await platform.check({ suspect: input, evidenceJson: pr.evidenceJson, passphrase: PW });
ok(T.checkView(unrelated).counts.matched === 0 && T.checkView(unrelated).commitOk, 'original (no canary) -> matched 0');

// commit_ok false: another key opening this evidence
await platform.deleteKey();
await platform.setupKey({ passphrase: PW });
let other = null;
try { other = await platform.check({ suspect: pr.marked, evidenceJson: pr.evidenceJson, passphrase: PW }); } catch (e) { other = e; }
if (other instanceof Error) {
  const v = T.errorView(other, { ctx: 'check' });
  ok(other.code === 'BAD_EVIDENCE' && v.hint.includes('Wrong key'), `other key -> ${other.code}, hint "Wrong key, or the evidence was tampered with"`);
} else {
  const v = T.checkView(other);
  ok(!v.commitOk && v.commitText === T.TEXT.commitBad, 'other key -> commit_ok false sentence');
}

// disclosure + verify sections with the original key
await platform.deleteKey();
// (the first key is gone; re-run the flow with a fresh key to get a disclosure)
await platform.setupKey({ passphrase: PW });
const pr2 = await platform.protect({ input: noSeq, datasetId: 'ui/test2', n: 8, passphrase: PW });
const rep2 = await platform.check({ suspect: pr2.marked, evidenceJson: pr2.evidenceJson, passphrase: PW });
const { disclosureJson } = await platform.disclose({ evidenceJson: pr2.evidenceJson, suspect: pr2.marked, indices: rep2.matched_indices.slice(0, 3), suspectMeta: { sourceClaim: 'https://example.com/x', capturedClaim: '2026-11-30T15:00:00Z', captureMethodClaim: 'save as' }, passphrase: PW });
ok(T.docKind(disclosureJson) === 'disclosure' && T.docKind(pr2.evidenceJson) === 'evidence' && T.docKind('{x') === null && T.docKind('{"schema":"z"}') === null, 'docKind: disclosure / evidence / null');
const dr = await platform.verifyDisclosure(disclosureJson, pr2.marked);
const dv = T.disclosureSections(dr);
ok(dv.pass === (dr.verdict.integrity_ok && dr.verdict.all_reproduced) && dv.pass === true, 'disclosure PASS = integrity_ok && all_reproduced');
ok(dv.sections.map(s => s.title).join('|') === '1. Evidence|2. Time anchor (a checked anchor with a wrong imprint FAILs; none is fine)|3. Copy|4. Disclosed canaries|5. Verdict', 'disclosure sections follow the WP-05 human output');
ok(dv.sections[3].items[0].text.endsWith('3/3') && dv.sections[3].items[1].text.endsWith('3/3') && dv.sections[3].items.length === 5, 'Merkle n/n, reproduced n/n, one line per disclosed index');
ok(dv.statement === dr.statement && /PASS/.test(dv.statement) && !/FAIL/.test(dv.statement.split('\n')[0]), 'statement verbatim (core text, language set by core)');
const tampered = pr2.marked.slice(); tampered[tampered.length - 2] ^= 1;
const dvBad = T.disclosureSections(await platform.verifyDisclosure(disclosureJson, tampered));
ok(!dvBad.pass && dvBad.sections[2].items[0].status === 'FAIL' && /FAIL/.test(dvBad.statement.split('\n')[0]), 'suspect changed by 1 byte -> FAIL, copy FAIL');
const ev = T.evidenceSections(await platform.verifyEvidence(pr2.evidenceJson));
ok(ev.pass && ev.sections.length === 3 && ev.sections[1].items[0].status === 'N/A', 'evidence sections: PASS, anchor N/A');
const evObj = JSON.parse(pr2.evidenceJson); evObj.sig_b64 = evObj.sig_b64.replace(/^./, c => (c === 'A' ? 'B' : 'A'));
let evBad;
try { evBad = T.evidenceSections(await platform.verifyEvidence(JSON.stringify(evObj))); } catch (e) { evBad = e; }
ok(evBad instanceof Error ? evBad.code === 'BAD_EVIDENCE' : evBad.pass === false, 'evidence with a changed signature -> FAIL (or BAD_EVIDENCE)');
let structural = null;
try { await platform.verifyDisclosure('{"schema":"norea.disclosure.v1"}', pr2.marked); } catch (e) { structural = e; }
ok(structural && ['BAD_DISCLOSURE', 'BAD_EVIDENCE'].includes(structural.code) && T.errorView(structural, { ctx: 'verify' }).hint !== null, `broken disclosure -> ${structural?.code} (structural, exit 2 equivalent) with hint`);

console.log(`ui.node.mjs: ${passed} passed`);
