// Integration test of the web platform contract v1 (platform-web.js + custody.js)
// through the PASSPHRASE path, in node with an in-memory IndexedDB (fake-indexeddb).
// Covered: 17-function surface, setup -> inspect -> protect -> check -> disclose ->
// verifyEvidence -> verifyDisclosure -> exportBackup -> deleteKey -> importBackup -> check,
// import validation (custody-web-v1 §3), error codes, no plaintext secret in IndexedDB,
// input immutability, created_claim format.
// NOT covered here: WebAuthn PRF and the DOM (app.js). Those need a real browser (WP-09).
//
// Run: node tests/platform.node.mjs <abs dir holding platform.js, platform-web.js, custody.js and pkg/>
// scripts/test.sh copies web/public/*.js to target/web-test/ and builds pkg/ there, so
// web/public/pkg stays the build-web.sh output.
import 'fake-indexeddb/auto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { webcrypto, hkdfSync } from 'node:crypto';

// node's fetch cannot read file: URLs; wasm-bindgen's init() needs that for the .wasm.
const realFetch = globalThis.fetch;
globalThis.fetch = async u => {
  const url = new URL(u);
  if (url.protocol === 'file:') return new Response(await readFile(url), { headers: { 'Content-Type': 'application/wasm' } });
  return realFetch(u);
};
globalThis.window = globalThis;

let passed = 0;
const ok = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } passed++; console.log('ok  ', m); };
// platform-contract "Errors" (fixed after WP-06, 2026-11-09): every contract error has one of these.
const CODES = ['KEY_MISSING', 'KEY_EXISTS', 'BAD_PASSPHRASE', 'PRF_UNSUPPORTED', 'CANCELLED', 'BAD_INPUT', 'NO_MARKER',
  'CANARY_EXHAUSTED', 'BAD_EVIDENCE', 'BAD_DISCLOSURE', 'ANCHOR_UNAVAILABLE', 'BACKUP_INVALID'];
// English message: has Latin letters and no Hangul syllables (U+AC00..U+D7A3).
const ENGLISH = s => /[A-Za-z]/.test(s) && !/[\uAC00-\uD7A3]/.test(s);
const seenErrors = [];
/** Resolves to the thrown error (or null if nothing was thrown). */
const thrown = async fn => { try { await fn(); return null; } catch (e) { seenErrors.push(e); return e; } };
const hasCode = async (fn, code) => { const e = await thrown(fn); return e?.code === code ? e : null; };

const root = process.argv[2];
const platform = await import(pathToFileURL(`${root}/platform.js`).href);
const pg = await import(pathToFileURL(`${root}/pkg/norea_web.js`).href); // same module instance as platform-web
const te = new TextEncoder(), td = new TextDecoder();

// ---------------------------------------------------------------- 1. contract surface
const EXPECTED = ['ready', 'capabilities', 'hasKey', 'keyInfo', 'setupKey', 'deleteKey', 'exportBackup', 'importBackup',
  'inspect', 'protect', 'anchor', 'check', 'disclose', 'verifyEvidence', 'verifyDisclosure', 'saveFile', 'confirmAction'];
ok(platform.CONTRACT.length === 17 && JSON.stringify(platform.CONTRACT) === JSON.stringify(EXPECTED), 'CONTRACT has the 17 names of platform-contract v1, in order');
const missing = platform.CONTRACT.filter(f => typeof platform[f] !== 'function');
ok(missing.length === 0, `platform.js exports all 17 contract functions${missing.length ? ' missing: ' + missing : ''}`);
const extra = Object.keys(platform).filter(k => k !== 'CONTRACT' && !platform.CONTRACT.includes(k));
ok(extra.length === 0, `platform.js exports nothing outside the contract${extra.length ? ': ' + extra : ''}`);

await platform.ready();
const caps = await platform.capabilities();
ok(caps.platform === 'web' && caps.hardwareDuringSigning === false && caps.anchorRelay === null && [true, false, 'unknown'].includes(caps.prf),
  `capabilities -> ${JSON.stringify(caps)} (hardwareDuringSigning false, ADR-0006)`);
ok(!(await platform.hasKey()) && (await platform.keyInfo()) === null, 'fresh state: hasKey false, keyInfo null');

// ---------------------------------------------------------------- 2. KEY_MISSING before setup
const PW = 'correct horse battery staple';
const CLAIM_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
function dataset(rows) {
  const si = ['하남시 미사동', '하남시 망월동', '성남시 정자동', '용인시 죽전동'];
  const out = [];
  for (let i = 0; i < rows; i++) out.push({ id: `P-${String(i * 3).padStart(6, '0')}`, addr: `${si[i % 4]} ${1 + (i * 7) % 997}-${1 + i % 37}`, area_m2: 50 + (i * 13) % 1950 + (i % 100) / 100, use: ['대', '전', '답'][i % 3] });
  return out;
}
const input = te.encode(JSON.stringify(dataset(500), null, 2));
const inputCopy = input.slice();
const ds = 'platform/test/2026-11';
ok(await hasCode(() => platform.protect({ input, datasetId: ds, n: 8, passphrase: PW }), 'KEY_MISSING'), 'protect without a key -> KEY_MISSING');
ok(await hasCode(() => platform.exportBackup(), 'KEY_MISSING'), 'exportBackup without a key -> KEY_MISSING');
// PRF path (setupKey without passphrase). node has no WebAuthn; then stubbed authenticators.
ok(await hasCode(() => platform.setupKey({}), 'PRF_UNSUPPORTED'), 'setupKey without passphrase and no WebAuthn -> PRF_UNSUPPORTED');
{
  const nav = globalThis.navigator;
  const stub = create => {
    globalThis.PublicKeyCredential = function PublicKeyCredential() {};
    Object.defineProperty(nav, 'credentials', { value: { create, get: create }, configurable: true });
  };
  try {
    stub(async () => { throw new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'); });
    ok(await hasCode(() => platform.setupKey({}), 'CANCELLED'), 'passkey prompt cancelled (NotAllowedError) -> CANCELLED');
    stub(async () => ({ rawId: new Uint8Array(16).buffer, getClientExtensionResults: () => ({ prf: { enabled: false } }) }));
    const e = await hasCode(() => platform.setupKey({}), 'PRF_UNSUPPORTED');
    ok(e && /left unused/.test(e.message), `authenticator without PRF -> PRF_UNSUPPORTED ("${e?.message}")`);
    ok(!(await platform.hasKey()), 'failed PRF setups stored nothing');
  } finally {
    delete nav.credentials;
    delete globalThis.PublicKeyCredential;
  }
}

// ---------------------------------------------------------------- 3. setup + IndexedDB record has no plaintext secret
const before = Date.now();
const backup = await platform.setupKey({ passphrase: PW });
const info = await platform.keyInfo();
ok(info?.method === 'passphrase' && /^[0-9a-f]{16}$/.test(info.fingerprint) && info.hardwareDuringSigning === false,
  `setupKey -> passphrase key, fingerprint ${info?.fingerprint}, hardwareDuringSigning false`);
ok(typeof info.createdClaim === 'string' && info.createdClaim.length === 20 && CLAIM_RE.test(info.createdClaim) &&
  Math.abs(Date.parse(info.createdClaim) - before) < 5000, `keyInfo.createdClaim ${info.createdClaim} is 20-char RFC 3339 UTC`);
ok(await hasCode(() => platform.setupKey({ passphrase: PW }), 'KEY_EXISTS'), 'setupKey with an existing key -> KEY_EXISTS');
ok(info.persisted === 'unknown', `keyInfo.persisted is "unknown" in node (no navigator.storage): ${JSON.stringify(info.persisted)}`);

function rawRecord() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('norea', 1);
    r.onsuccess = () => { const g = r.result.transaction('custody').objectStore('custody').get('v1'); g.onsuccess = () => { r.result.close(); res(g.result); }; g.onerror = () => rej(g.error); };
    r.onerror = () => rej(r.error);
  });
}
const rec = await rawRecord();
ok(JSON.stringify(Object.keys(rec).sort()) === JSON.stringify(['createdClaim', 'ct', 'iv', 'kdf', 'method', 'salt', 'v', 'vk']),
  `IndexedDB norea/custody/v1 keys: ${Object.keys(rec).sort().join(', ')}`);
ok(rec.v === 1 && rec.iv.length === 12 && rec.ct.length === 80 && rec.vk.length === 1952 && rec.salt.length === 16 &&
  JSON.stringify(rec.kdf) === '{"alg":"argon2id","m":65536,"t":3,"p":1}', 'record: iv 12 B, ct 80 B, vk 1952 B, salt 16 B, kdf argon2id 65536/3/1');
// Recover K || seed independently of custody.js: Argon2id (WASM) -> HKDF -> AES-GCM.
const S = pg.passphraseKek(PW, rec.salt);
const kekRaw = new Uint8Array(hkdfSync('sha256', S, new Uint8Array(32), te.encode('norea/kek/v1'), 32));
const kek = await webcrypto.subtle.importKey('raw', kekRaw, 'AES-GCM', false, ['decrypt']);
const secrets = new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: te.encode('norea/custody/v1') }, kek, rec.ct));
const K = secrets.slice(0, 32), SEED = secrets.slice(32, 64);
ok(Buffer.from(pg.verifyingKey(SEED.slice())).equals(Buffer.from(rec.vk)), 'record decrypts with the spec KEK derivation; vk == verifyingKey(seed)');
const containsSecret = u8 => {
  const hay = Buffer.from(u8);
  for (const sec of [K, SEED]) for (let o = 0; o + 8 <= 32; o++) if (hay.indexOf(Buffer.from(sec.subarray(o, o + 8))) !== -1) return true;
  return false;
};
const textHasSecret = t => [K, SEED].some(s => t.includes(Buffer.from(s).toString('hex')) || t.includes(Buffer.from(s).toString('base64').slice(0, 16)));
ok(!['salt', 'iv', 'ct', 'vk'].some(f => containsSecret(rec[f])) && !textHasSecret(JSON.stringify(rec)),
  'no record field contains K or seed (any 8-byte window, hex, base64)');
const bj = JSON.parse(td.decode(backup));
ok(bj.format === 'norea.custody-backup.v1' && bj.v === 1 && bj.method === 'passphrase' && !containsSecret(backup) && !textHasSecret(td.decode(backup)),
  'backup is norea.custody-backup.v1 with the encrypted blob only');
ok(JSON.stringify(Object.keys(bj)) === JSON.stringify(['format', 'v', 'method', 'kdf', 'salt', 'iv', 'ct', 'vk', 'createdClaim']),
  `backup keys in spec order: ${Object.keys(bj).join(', ')}`);

// ---------------------------------------------------------------- 4. inspect, protect
const ins = await platform.inspect({ input });
ok(ins.format === 'json' && ins.rows === 500 && ins.suggestedMarkers.length > 0, `inspect -> json, 500 rows, markers ${ins.suggestedMarkers}`);
const p = await platform.protect({ input, datasetId: ds, n: 16, passphrase: PW });
ok(input.length === inputCopy.length && input.every((b, i) => b === inputCopy[i]), 'protect did not modify the input bytes');
const ev = JSON.parse(p.evidenceJson);
ok(p.evidenceId === ev.evidence_id && p.summary.evidenceId === ev.evidence_id && p.summary.rows === 500 && p.summary.canaries === 16 &&
  JSON.stringify(p.summary.markers) === JSON.stringify(ev.marker_fields) && p.summary.threshold === Math.min(2, ev.marker_fields.length) && p.summary.format === 'json',
  `protect -> evidenceId ${p.evidenceId.slice(0, 16)}..., summary ${JSON.stringify(p.summary)}`);
ok(ev.created_claim.length === 20 && CLAIM_RE.test(ev.created_claim) && Math.abs(Date.parse(ev.created_claim) - Date.now()) < 5000,
  `evidence created_claim ${ev.created_claim}: exactly 20 chars, toISOString().slice(0,19)+'Z'`);
ok(JSON.parse(td.decode(p.marked)).length === 516, 'marked -> 500 + 16 rows');
ok(!containsSecret(p.marked) && !textHasSecret(p.evidenceJson), 'marked and evidence contain no K or seed');
const csvIn = te.encode('id,addr,area_m2,use\nP-013,하남시 미사동 1-1,330.5,대\nP-027,하남시 미사동 2-7,512.0,전\nP-102,하남시 미사동 3-2,87.8,답\nP-245,하남시 망월동 4-4,120.25,대\nP-318,하남시 망월동 5-9,45.0,전\nP-406,하남시 미사동 6-1,999.99,대\n');
const pc = await platform.protect({ input: csvIn, format: 'csv', datasetId: 'csv/1', n: 4, passphrase: PW });
ok(pc.summary.format === 'csv' && td.decode(pc.marked).split('\n').length === 12, 'protect(csv) -> csv with 6 + 4 rows');

// ---------------------------------------------------------------- 5. error codes
let e = await hasCode(() => platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: 'wrong passphrase' }), 'BAD_PASSPHRASE');
ok(e, `wrong passphrase -> BAD_PASSPHRASE ("${e?.message}")`);
ok(await hasCode(() => platform.protect({ input, datasetId: ds, n: 4 }), 'BAD_PASSPHRASE'), 'missing passphrase -> BAD_PASSPHRASE');
e = await hasCode(() => platform.protect({ input: te.encode('a,b\n1,2,3\n'), datasetId: ds, n: 4, passphrase: PW }), 'BAD_INPUT');
ok(e && /^BadInput: /.test(e.detail), `CSV column mismatch -> BAD_INPUT ("${e?.message}", detail "${e?.detail}")`);
ok(await hasCode(() => platform.inspect({ input: te.encode('a,b\n1,2,3\n') }), 'BAD_INPUT'), 'inspect(CSV column mismatch) -> BAD_INPUT');
ok(await hasCode(() => platform.protect({ input: 'not bytes', datasetId: ds, n: 4, passphrase: PW }), 'BAD_INPUT'), 'protect(input not Uint8Array) -> BAD_INPUT');
const dense = te.encode(JSON.stringify(['P-001', 'P-002', 'P-003', 'P-004', 'P-005', 'P-006'].map((id, i) => ({ id, addr: `하남시 미사동 ${i + 1}-1`, area_m2: 100 + i, use: '대' }))));
ok(await hasCode(() => platform.protect({ input: dense, datasetId: ds, n: 4, passphrase: PW }), 'NO_MARKER'), 'no usable marker field -> NO_MARKER');
const wp03 = te.encode('[{"id":"P-001","addr":"하남시 미사동 1-1","area_m2":330.5,"use":"대"},{"id":"P-002","addr":"하남시 미사동 2-7","area_m2":512.0,"use":"전"},{"id":"P-003","addr":"하남시 미사동 3-2","area_m2":87.8,"use":"답"},{"id":"P-004","addr":"하남시 망월동 4-4","area_m2":120.25,"use":"대"},{"id":"P-005","addr":"하남시 망월동 5-9","area_m2":45.0,"use":"전"},{"id":"P-006","addr":"하남시 미사동 6-1","area_m2":999.99,"use":"대"}]');
ok(await hasCode(() => platform.protect({ input: wp03, datasetId: ds, n: 4, passphrase: PW }), 'CANARY_EXHAUSTED'), 'dense unique id -> CANARY_EXHAUSTED');
e = await hasCode(() => platform.anchor({ evidenceJson: p.evidenceJson }), 'ANCHOR_UNAVAILABLE');
ok(e && e.message === 'No anchor relay is configured. Use the CLI: norea anchor <evidence.json> --tsa URL', 'anchor with anchorRelay null -> ANCHOR_UNAVAILABLE, points to the CLI');
ok(await hasCode(() => platform.check({ suspect: p.marked, evidenceJson: '{bad', passphrase: PW }), 'BAD_EVIDENCE'), 'check(malformed evidence) -> BAD_EVIDENCE');
ok(await hasCode(() => platform.check({ suspect: p.marked, evidenceJson: 42, passphrase: PW }), 'BAD_EVIDENCE'), 'check(evidence not a string) -> BAD_EVIDENCE');
const forged = JSON.stringify({ ...ev, sig_b64: (ev.sig_b64[0] === 'A' ? 'B' : 'A') + ev.sig_b64.slice(1) });
e = await hasCode(() => platform.disclose({ evidenceJson: forged, suspect: p.marked, passphrase: PW }), 'BAD_EVIDENCE');
ok(e && /^BadEvidence: /.test(e.detail), `disclose(evidence with a changed signature) -> BAD_EVIDENCE (detail "${e?.detail}")`);
ok(await hasCode(() => platform.disclose({ evidenceJson: p.evidenceJson, suspect: p.marked, indices: [-1], passphrase: PW }), 'BAD_DISCLOSURE'), 'disclose(indices [-1]) -> BAD_DISCLOSURE');
e = await hasCode(() => platform.disclose({ evidenceJson: p.evidenceJson, suspect: input, indices: [0], passphrase: PW }), 'BAD_DISCLOSURE');
ok(e && /^BadDisclosure: /.test(e.detail), `disclose(index not matched in the suspect) -> BAD_DISCLOSURE (detail "${e?.detail}")`);

// ---------------------------------------------------------------- 6. check, disclose, verify
const rep = await platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: PW });
ok(rep.schema === 'norea.check-report.v1' && rep.matched === 16 && rep.commit_ok === true, `check(marked) -> matched ${rep.matched}/16`);
const meta = { sourceClaim: 'https://example.com/copy.json', capturedClaim: '2026-11-09T10:00:00Z', captureMethodClaim: 'browser save-as' };
const { disclosureJson } = await platform.disclose({ evidenceJson: p.evidenceJson, suspect: p.marked, indices: [0, 5], suspectMeta: meta, passphrase: PW });
const dsc = JSON.parse(disclosureJson);
ok(dsc.schema === 'norea.disclosure.v1' && dsc.disclosed.map(x => x.index).join() === '0,5' && dsc.suspect.source_claim === meta.sourceClaim &&
  dsc.suspect.captured_claim === meta.capturedClaim && dsc.suspect.capture_method_claim === meta.captureMethodClaim && CLAIM_RE.test(dsc.created_claim),
  'disclose(indices [0,5], suspectMeta) -> 2 disclosed, claims mapped, created_claim 20 chars');
const all = JSON.parse((await platform.disclose({ evidenceJson: p.evidenceJson, suspect: p.marked, passphrase: PW })).disclosureJson);
ok(all.disclosed.length === 16, 'disclose(no indices) -> every matched canary');
ok(!textHasSecret(disclosureJson), 'disclosure contains no K or seed');
const v = await platform.verifyEvidence(p.evidenceJson);
ok(v.signatureOk === true && v.evidenceIdOk === true && v.blobHashOk === true && v.hasAnchors === false && Array.isArray(v.anchors),
  `verifyEvidence -> ${JSON.stringify(v)}`);
const vb = await platform.verifyEvidence(JSON.stringify({ ...ev, created_claim: '2020-01-01T00:00:00Z' }));
ok(vb.signatureOk === false, 'verifyEvidence(backdated) -> signatureOk false');
const pass = r => r.verdict.integrity_ok && r.verdict.all_reproduced;
const vr = await platform.verifyDisclosure(disclosureJson, p.marked);
ok(vr.schema === 'norea.disclosure-report.v1' && pass(vr) && vr.summary.matched === 2, 'verifyDisclosure -> PASS (verdict.integrity_ok && all_reproduced), 2 reproduced');
const tampered = p.marked.slice(); tampered[10] ^= 1;
ok(!pass(await platform.verifyDisclosure(disclosureJson, tampered)), 'verifyDisclosure(changed suspect) -> FAIL');
ok(await hasCode(() => platform.verifyDisclosure('{', p.marked), 'BAD_DISCLOSURE'), 'verifyDisclosure(malformed) -> BAD_DISCLOSURE (structural error)');

// ---------------------------------------------------------------- 7. backup -> delete -> import -> check
const exported = await platform.exportBackup();
ok(td.decode(exported) === td.decode(backup), 'exportBackup == the backup returned by setupKey');
await platform.deleteKey();
ok(!(await platform.hasKey()) && (await platform.keyInfo()) === null, 'deleteKey -> no key');
ok(await hasCode(() => platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: PW }), 'KEY_MISSING'), 'check after deleteKey -> KEY_MISSING');
await platform.importBackup(backup);
const info2 = await platform.keyInfo();
ok(info2.fingerprint === info.fingerprint && info2.createdClaim === info.createdClaim && info2.persisted === 'unknown', 'importBackup restored the same key and createdClaim; persisted "unknown"');
const rep2 = await platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: PW });
ok(rep2.matched === 16, 'restored key still opens old evidence (check matched 16)');

// ---------------------------------------------------------------- 8. import validation (custody-web-v1 §3)
const b64 = u8 => Buffer.from(u8).toString('base64');
const variant = f => { const j = JSON.parse(td.decode(backup)); f(j); return te.encode(JSON.stringify(j)); };
const rejects = [
  ['ct 79 B', j => { j.ct = b64(Buffer.from(j.ct, 'base64').subarray(0, 79)); }],
  ['ct 81 B', j => { j.ct = b64(Buffer.concat([Buffer.from(j.ct, 'base64'), Buffer.from([0])])); }],
  ['format wrong', j => { j.format = 'norea.custody-backup.v2'; }],
  ['format missing', j => { delete j.format; }],
  ['v 2', j => { j.v = 2; }],
  ['method unknown', j => { j.method = 'tpm-sealed'; }],
  ['kdf.m 8191', j => { j.kdf.m = 8191; }],
  ['kdf.m 1048577', j => { j.kdf.m = 1048577; }],
  ['kdf.t 11', j => { j.kdf.t = 11; }],
  ['kdf.p 2', j => { j.kdf.p = 2; }],
  ['kdf.alg scrypt', j => { j.kdf.alg = 'scrypt'; }],
  ['salt 15 B', j => { j.salt = b64(new Uint8Array(15)); }],
  ['salt 65 B', j => { j.salt = b64(new Uint8Array(65)); }],
  ['iv 11 B', j => { j.iv = b64(new Uint8Array(11)); }],
  ['vk 1951 B', j => { j.vk = b64(new Uint8Array(1951)); }],
  ['ct not base64', j => { j.ct = '***' + j.ct.slice(3); }],
  ['prf without credId', j => { j.method = 'prf'; }],
  ['prf credId 15 B', j => { j.method = 'prf'; j.credId = b64(new Uint8Array(15)); }],
];
for (const [name, f] of rejects) {
  const err = await hasCode(() => platform.importBackup(variant(f)), 'BACKUP_INVALID');
  ok(err, `importBackup rejects ${name} -> BACKUP_INVALID ("${err?.message}")`);
}
ok(await hasCode(() => platform.importBackup(te.encode('not json')), 'BACKUP_INVALID'), 'importBackup rejects non-JSON -> BACKUP_INVALID');
ok((await platform.keyInfo()).fingerprint === info.fingerprint, 'rejected imports left the stored key unchanged');
await platform.importBackup(variant(j => { j.extra = 'x'; j.seed = 'AAAA'; j.kdf.extra = 1; }));
const rec2 = await rawRecord();
ok(!('extra' in rec2) && !('seed' in rec2) && !('extra' in rec2.kdf) && (await platform.keyInfo()).fingerprint === info.fingerprint,
  'importBackup with unknown keys -> accepted, unknown keys dropped');
ok(!td.decode(await platform.exportBackup()).includes('extra'), 'unknown keys do not come back in exportBackup');
await platform.importBackup(variant(j => { j.kdf.m = 8192; }));
ok(await hasCode(() => platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: PW }), 'BACKUP_INVALID'),
  'backup with kdf.m 8192 imports (in §3 range) but cannot be opened by this version -> BACKUP_INVALID');
await platform.importBackup(backup);
ok((await platform.check({ suspect: p.marked, evidenceJson: p.evidenceJson, passphrase: PW })).matched === 16, 're-import of the original backup works again');

// ---------------------------------------------------------------- 9. UI helpers (stubbed DOM)
let confirmed = null; globalThis.confirm = m => { confirmed = m; return true; };
ok((await platform.confirmAction('Delete?')) === true && confirmed === 'Delete?', 'confirmAction -> window.confirm');
let saved = null;
globalThis.document = { createElement: () => ({ click() { saved = { name: this.download, href: this.href }; } }) };
await platform.saveFile('x.evidence.json', te.encode('{}'), 'application/json');
ok(saved?.name === 'x.evidence.json' && saved.href.startsWith('blob:'), 'saveFile -> <a download> with a blob URL');

// ---------------------------------------------------------------- 9b. anchor through a relay (WP-08), fetch stubbed
{
  const { config } = await import(pathToFileURL(`${root}/config.js`).href); // same instance platform-web reads
  const vec = JSON.parse(await readFile(new URL('./vectors/norea-evidence-v1.json', import.meta.url), 'utf8'));
  const vecEv = JSON.stringify(vec.json.evidence);
  const fixture = await readFile(new URL('./fixtures/tsa-response-freetsa-vector-json.der', import.meta.url));
  const foreign = await readFile(new URL('../core/tests/fixtures/tsa-response-freetsa.der', import.meta.url));
  const saveFetch = globalThis.fetch;
  const calls = [];
  let reply = () => new Response(fixture, { status: 200, headers: { 'Content-Type': 'application/timestamp-reply' } });
  globalThis.fetch = async (u, o) => { calls.push({ u: String(u), o }); return reply(); };
  config.anchorRelay = 'http://localhost:8787';
  try {
    ok((await platform.capabilities()).anchorRelay === 'http://localhost:8787', 'capabilities().anchorRelay reflects config.js');
    const r = await platform.anchor({ evidenceJson: vecEv });
    const c = calls[0];
    const body = new Uint8Array(c.o.body);
    ok(calls.length === 1 && c.u === 'http://localhost:8787/v1/tsa' && c.o.method === 'POST' && c.o.headers['Content-Type'] === 'application/timestamp-query' &&
      c.o.headers['X-TSA-URL'] === 'https://freetsa.org/tsr' && c.o.credentials === 'omit', 'anchor POSTs the TimeStampReq to <relay>/v1/tsa with X-TSA-URL from config');
    const bodyHex = Buffer.from(body).toString('hex');
    // 59 B without nonce; an 8-byte nonce INTEGER adds 2 + 1..9 bytes (leading zeros stripped, 0x00 pad on a high bit).
    ok(body[0] === 0x30 && body.length >= 62 && body.length <= 70 && bodyHex.includes(vec.json.anchor_subject_hex) && bodyHex.endsWith('0101ff'),
      `request body: TimeStampReq with the anchor_subject imprint and a random nonce (${body.length} B)`);
    ok(!bodyHex.includes(Buffer.from(vec.json.evidence.sig_b64, 'base64').subarray(0, 32).toString('hex')) && !td.decode(body).includes(vec.json.evidence.dataset_id),
      'request body carries no evidence fields (only the imprint and nonce)');
    ok(r.results.length === 1 && r.results[0].kind === 'rfc3161' && r.results[0].ok === true, `anchor -> results ${JSON.stringify(r.results)}`);
    const a = JSON.parse(r.evidenceJson).anchors[0];
    ok(a.tsa_url === 'https://freetsa.org/tsr' && CLAIM_RE.test(a.fetched_claim) && typeof a.token_b64 === 'string', 'anchor entry: tsa_url, fetched_claim (UTC, 20 chars), token_b64');
    const v = await platform.verifyEvidence(r.evidenceJson);
    ok(v.signatureOk && v.anchors[0].imprintOk === true && v.anchors[0].genTime === '2026-11-09T04:55:37Z' && v.anchors[0].chainVerified === false,
      `anchored evidence verifies: imprintOk, genTime ${v.anchors[0].genTime}, chainVerified false`);

    reply = () => new Response(foreign, { status: 200 });
    const bad = await platform.anchor({ evidenceJson: vecEv });
    ok(bad.results[0].ok === false && /imprint does not match/.test(bad.results[0].error) && bad.evidenceJson === vecEv,
      'relay returns a token for another imprint -> results[0].ok false (reported, not thrown), evidence unchanged');
    reply = () => new Response('TSA answered HTTP 500\n', { status: 502 });
    const down = await platform.anchor({ evidenceJson: vecEv });
    ok(down.results[0].ok === false && /HTTP 502/.test(down.results[0].error), `relay HTTP 502 -> reported: ${down.results[0].error}`);
    reply = () => { throw new TypeError('Failed to fetch'); };
    const off = await platform.anchor({ evidenceJson: vecEv, kinds: ['rfc3161', 'ots'] });
    ok(off.results.length === 2 && !off.results[0].ok && /could not be reached/.test(off.results[0].error) && !off.results[1].ok && /ots/.test(off.results[1].error),
      'relay unreachable and kind ots -> both reported in results');
    ok(await hasCode(() => platform.anchor({ evidenceJson: '{bad' }), 'BAD_EVIDENCE'), 'anchor(malformed evidence) -> BAD_EVIDENCE before any request');
    config.anchorRelay = 'http://localhost:8787/path';
    ok((await platform.capabilities()).anchorRelay === null, 'anchorRelay that is not a bare origin is ignored (null)');

    // Live check through the real dev relay and freetsa.org, only when asked (needs network).
    if (process.env.NOREA_LIVE_RELAY) {
      globalThis.fetch = (u, o) => realFetch(u, o);
      config.anchorRelay = process.env.NOREA_LIVE_RELAY;
      const live = await platform.anchor({ evidenceJson: p.evidenceJson });
      const lv = live.results[0].ok ? await platform.verifyEvidence(live.evidenceJson) : null;
      ok(lv?.anchors[0].imprintOk === true, `LIVE relay ${config.anchorRelay}: ${JSON.stringify(live.results)}, genTime ${lv?.anchors[0].genTime}`);
    } else {
      console.log('skip  live relay test (requires network): set NOREA_LIVE_RELAY=http://localhost:8787 with scripts/dev-relay.mjs running');
    }
  } finally {
    globalThis.fetch = saveFetch;
    config.anchorRelay = null;
  }
}

// ---------------------------------------------------------------- 10. every error seen: English message, contract code, no secrets
const noCode = seenErrors.filter(x => !CODES.includes(x.code));
ok(seenErrors.length > 0 && noCode.length === 0 && seenErrors.every(x => ENGLISH(x.message)),
  `all ${seenErrors.length} thrown errors have an English message and a contract code${noCode.length ? '; without: ' + noCode.map(x => x.message) : ''}`);
const used = [...new Set(seenErrors.map(x => x.code))].sort();
ok(used.length === CODES.length, `every contract code was produced at least once: ${used.join(', ')}`);
ok(seenErrors.every(x => !textHasSecret(`${x.message} ${x.detail ?? ''}`) && !/[/\\][\w.-]+[/\\]/.test(x.message) && !/\n\s+at /.test(x.message)),
  'no error message or detail contains K, seed, a path or a stack');

console.log(`ALL PLATFORM CONTRACT TESTS PASSED (${passed})`);
process.exit(0); // saveFile's revokeObjectURL timer would keep node alive 10 s
