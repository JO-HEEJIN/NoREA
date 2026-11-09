// End-to-end test of the exact WASM API the browser uses (CORE-API §2, 12 functions),
// plus the ADR-0012 memory scan and the frozen-vector cross-check.
// Run: node tests/smoke.node.cjs <dir with wasm-bindgen --target nodejs output>
//
// Memory scan method: the nodejs glue keeps its `wasm` instance private, so this
// test compiles the unmodified glue file with one appended line that exports it
// (`module.exports.__wasm = wasm`). After each secret-taking call the whole linear
// memory (`wasm.memory.buffer`: heap, shadow stack, static data) is searched for
// the 32-byte K and seed, and for every 16-byte window of them. A positive control
// shows the scanner finds a secret that was passed the wrong way (`&[u8]`).
// The binding's stack layout is stack-first (rustc wasm32 default): the shadow
// stack is [0, 1 MiB) and grows down from 1 MiB, data starts at 1 MiB. The test
// also counts non-zero bytes left in that region after each secret-taking call
// (web/src/lib.rs zeroes the stack its secret frames used).
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const crypto = require('node:crypto');

const dir = path.resolve(process.argv[2] || '');
const gluePath = path.join(dir, 'norea_web.js');
const glue = new Module(gluePath, module);
glue.filename = gluePath;
glue.paths = Module._nodeModulePaths(dir);
glue._compile(fs.readFileSync(gluePath, 'utf8') + '\nmodule.exports.__wasm = wasm;\n', gluePath);
const pg = glue.exports;

const te = new TextEncoder(), td = new TextDecoder();
let passed = 0;
const ok = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } passed++; console.log('ok  ', m); };
const throwsCode = (fn, re) => { try { fn(); return null; } catch (e) { return re.test(String(e.message)) ? e.message : null; } };
const hexOf = u8 => Buffer.from(u8).toString('hex');
const hkdf = (ikm, salt, info) => new Uint8Array(crypto.hkdfSync('sha256', ikm, te.encode(salt), info, 32));
const CODE_RE = /^(BadInput|NoMarker|CanaryExhausted|BadEvidence|BadSignature|BadBlob|BadDisclosure|BadAnchor|ANCHOR_UNAVAILABLE): \S/;

// ---------------------------------------------------------------- memory scan
function memory() { return Buffer.from(pg.__wasm.memory.buffer); }
/** Occurrences of the full secret and of each 16-byte window of it. */
function scan(secret) {
  const mem = memory();
  const count = needle => { let n = 0, i = -1; while ((i = mem.indexOf(needle, i + 1)) !== -1) n++; return n; };
  const full = count(Buffer.from(secret));
  let win16 = 0;
  for (let o = 0; o + 16 <= secret.length; o++) win16 += count(Buffer.from(secret.subarray(o, o + 16)));
  return { full, win16, memBytes: mem.length };
}
const STACK_TOP = 1 << 20;
/** Non-zero bytes left in the shadow stack region [0, 1 MiB). */
function stackResidue() {
  const m = new Uint8Array(pg.__wasm.memory.buffer, 0, STACK_TOP);
  let n = 0; for (let i = 0; i < m.length; i++) if (m[i] !== 0) n++;
  return n;
}
function scanAll(label, secrets) {
  const out = {};
  for (const [name, s] of Object.entries(secrets)) out[name] = scan(s);
  const desc = Object.entries(out).map(([n, r]) => `${n} ${r.full}/${r.win16}`).join(', ');
  console.log(`      scan after ${label} (memory ${(Object.values(out)[0].memBytes / 1048576).toFixed(1)} MiB; full/16B-window hits): ${desc}`);
  return out;
}

// ---------------------------------------------------------------- 1. export surface
const API = ['inspect', 'protect', 'check', 'disclose', 'verifyEvidence', 'verifyDisclosure', 'anchorSubjectHex',
  'tsaRequest', 'attachAnchor', 'verifyingKey', 'sha256Hex', 'passphraseKek'];
ok(API.every(f => typeof pg[f] === 'function') && typeof pg.ProtectResult === 'function',
  'exports the 12 CORE-API §2 functions and ProtectResult');

// ---------------------------------------------------------------- 2. frozen vector through WASM
const vec = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'norea-evidence-v1.json'), 'utf8'));
const VK = Buffer.from(vec.k_hex, 'hex'), VSEED = Buffer.from(vec.seed_hex, 'hex');
for (const kind of ['json', 'csv']) {
  const c = vec[kind];
  const r = pg.protect(te.encode(c.input_utf8), new Uint8Array(VK), new Uint8Array(VSEED), vec.dataset_id,
    JSON.stringify({ n: vec.n, markerFields: null, exclusions: [], format: null }), vec.created_claim);
  const evJson = r.evidenceJson, marked = r.marked;
  r.free();
  const ev = JSON.parse(evJson);
  ok(ev.evidence_id === c.evidence_id, `vector ${kind}: protect evidence_id == frozen ${c.evidence_id.slice(0, 16)}...`);
  ok(td.decode(marked) === c.marked_utf8, `vector ${kind}: marked bytes == frozen marked_utf8`);
  ok(JSON.stringify(ev) === JSON.stringify(c.evidence), `vector ${kind}: evidence JSON == frozen evidence object (key order and values)`);
  ok(pg.anchorSubjectHex(evJson) === c.anchor_subject_hex, `vector ${kind}: anchorSubjectHex == frozen anchor_subject_hex`);
  const rep = JSON.parse(pg.check(marked, new Uint8Array(VK), evJson));
  ok(rep.matched === 4 && rep.commit_ok === true, `vector ${kind}: check(marked) matched ${rep.matched}/4`);
}
const vvk = pg.verifyingKey(new Uint8Array(VSEED));
ok(vvk.length === 1952 && crypto.createHash('sha256').update(vvk).digest('hex') === vec.json.vk_sha256,
  'verifyingKey(vector seed) -> 1952 B, sha256 == frozen vk_sha256');

// ---------------------------------------------------------------- 3. inspect
function dataset(rows, mult = 3) {
  const si = ['하남시 미사동', '하남시 망월동', '성남시 정자동', '용인시 죽전동'];
  const use = ['대', '전', '답'];
  const out = [];
  for (let i = 0; i < rows; i++) {
    out.push(`  {"id": "P-${String(i * mult).padStart(6, '0')}", "addr": "${si[i % 4]} ${1 + (i * 7) % 997}-${1 + i % 37}", ` +
      `"area_m2": ${50 + (i * 13) % 1950}.${String(i % 100).padStart(2, '0')}, "use": "${use[i % 3]}"}`);
  }
  return te.encode(`[\n${out.join(',\n')}\n]\n`);
}
const input = dataset(2000);
const ins = JSON.parse(pg.inspect(input));
ok(ins.format === 'json' && ins.rows === 2000 && Array.isArray(ins.fields) && ins.suggestedMarkers.length >= 1 && ins.threshold >= 1,
  `inspect -> json, 2000 rows, markers ${JSON.stringify(ins.suggestedMarkers)}, threshold ${ins.threshold}`);
const insCsv = JSON.parse(pg.inspect(te.encode(vec.csv.input_utf8), 'csv'));
ok(insCsv.format === 'csv' && insCsv.rows === 6, 'inspect(csv, "csv") -> csv, 6 rows');
ok(throwsCode(() => pg.inspect(te.encode('a,b\n1,2,3\n')), /^BadInput: /), 'inspect: CSV column mismatch -> BadInput');
ok(throwsCode(() => pg.inspect(input, 'xml'), /^BadInput: /), 'inspect: unknown format -> BadInput');

// ---------------------------------------------------------------- 4. protect + memory scan
const K = crypto.randomBytes(32), SEED = crypto.randomBytes(32);
const ds = 'smoke/parcels/2026-11';
const claim = new Date().toISOString().slice(0, 19) + 'Z';
const inputCopy = Buffer.from(input);
const kArg = new Uint8Array(K), sArg = new Uint8Array(SEED);
const pr = pg.protect(input, kArg, sArg, ds, JSON.stringify({ n: 16, markerFields: null, exclusions: [], format: null }), claim);
kArg.fill(0); sArg.fill(0); // what platform-web/custody do after the call
ok(Buffer.compare(inputCopy, Buffer.from(input)) === 0, 'protect did not modify the input Uint8Array (byte compare)');
const marked = pr.marked, evJson = pr.evidenceJson;
pr.free();
ok(throwsCode(() => pr.evidenceJson, /./) !== null, 'ProtectResult getters throw after free()');
const ev = JSON.parse(evJson);
ok(ev.schema === 'norea.evidence.v1' && ev.canary_count === 16 && ev.created_claim === claim,
  `protect -> evidence v1, 16 canaries, created_claim ${claim}`);
ok(JSON.parse(td.decode(marked)).length === 2016, 'protect -> marked JSON with 2000 + 16 rows');
ok(Buffer.from(ev.vk_b64, 'base64').equals(Buffer.from(pg.verifyingKey(new Uint8Array(SEED)))), 'evidence vk == verifyingKey(seed)');

const KD = hkdf(K, 'norea/v1', te.encode(ds));
const KBLOB = hkdf(KD, 'norea/canary-blob/v1', Buffer.from(ev.marked_sha256, 'hex'));
const secrets = { K, seed: SEED, K_d: KD, K_blob: KBLOB };
// verifyingKey(SEED) above also took the seed (Vec<u8>, wiped); scan covers it too.
let s = scanAll('protect + verifyingKey', secrets);
ok(s.K.full === 0 && s.seed.full === 0, `memory scan after protect: K 32 B hits ${s.K.full}, seed 32 B hits ${s.seed.full}`);
ok(s.K.win16 === 0 && s.seed.win16 === 0, `memory scan after protect: 16 B windows of K ${s.K.win16}, of seed ${s.seed.win16}`);
ok(s.K_d.full + s.K_d.win16 + s.K_blob.full + s.K_blob.win16 === 0, `memory scan after protect: K_d ${s.K_d.full}/${s.K_d.win16}, K_blob ${s.K_blob.full}/${s.K_blob.win16}`);
let sr = stackResidue();
ok(sr < 1024, `stack region after protect: ${sr} non-zero bytes left of 1 MiB (deep frames zeroed)`);
const leaked = [evJson, td.decode(marked)].some(t => [K, SEED, KD, KBLOB].some(x =>
  t.includes(hexOf(x)) || t.includes(Buffer.from(x).toString('base64').slice(0, 20))));
ok(!leaked, 'evidence and marked contain no K, seed, K_d, K_blob (hex or base64)');

// ---------------------------------------------------------------- 5. check
const rep = JSON.parse(pg.check(marked, new Uint8Array(K), evJson));
ok(rep.schema === 'norea.check-report.v1' && rep.matched === 16 && rep.commit_ok === true && rep.evidence.signature_ok,
  `check(marked) -> matched ${rep.matched}/16, commit_ok, signature_ok`);
const copy = te.encode(JSON.stringify({ data: JSON.parse(td.decode(marked)).reverse().map(r => ({ name: r.id, where: r.addr, sqm: String(r.area_m2), u: r.use })) }));
const rep2 = JSON.parse(pg.check(copy, new Uint8Array(K), evJson));
ok(rep2.matched === 16, `check(renamed keys, reversed, nested, numbers as strings) -> matched ${rep2.matched}/16`);
const repW = JSON.parse(pg.check(marked, crypto.randomBytes(32), evJson));
ok(repW.matched === 0 && repW.commit_ok === false, 'check with wrong K -> commit_ok false, matched 0');
const repU = JSON.parse(pg.check(input, new Uint8Array(K), evJson));
ok(repU.matched === 0, 'check(original without canaries) -> matched 0');
ok(throwsCode(() => pg.check(marked, new Uint8Array(K), '{not json'), /^BadEvidence: /), 'check: malformed evidence -> BadEvidence');
ok(throwsCode(() => pg.check(marked, new Uint8Array(31), evJson), /^BadInput: masterK must be exactly 32 bytes/), 'check: 31-byte K -> BadInput');
s = scanAll('check', secrets);
ok(s.K.full + s.K.win16 + s.K_d.full + s.K_d.win16 + s.K_blob.full + s.K_blob.win16 === 0, `memory scan after check: K ${s.K.full}/${s.K.win16}, K_d ${s.K_d.full}/${s.K_d.win16}, K_blob ${s.K_blob.full}/${s.K_blob.win16}`);
sr = stackResidue();
ok(sr < 1024, `stack region after check: ${sr} non-zero bytes`);

// ---------------------------------------------------------------- 6. disclose + verifyDisclosure
const meta = JSON.stringify({ sourceClaim: 'https://example.com/data.json', capturedClaim: '2026-11-09T10:00:00Z', captureMethodClaim: 'browser save-as' });
const dj = pg.disclose(evJson, new Uint8Array(K), marked, 'null', meta, claim, false);
const d = JSON.parse(dj);
ok(d.schema === 'norea.disclosure.v1' && d.disclosed.length === 16, `disclose(indices null) -> ${d.disclosed.length} disclosed`);
ok(d.suspect.source_claim === 'https://example.com/data.json' && d.suspect.captured_claim === '2026-11-09T10:00:00Z' &&
  d.suspect.capture_method_claim === 'browser save-as', 'disclose: metaJson camelCase keys -> suspect.*_claim');
const d0 = JSON.parse(pg.disclose(evJson, new Uint8Array(K), marked, '[3]', '', claim, false));
ok(d0.disclosed.length === 1 && d0.disclosed[0].index === 3 && !('source_claim' in d0.suspect), 'disclose(indices [3], metaJson "") -> 1 disclosed, no claims');
const dAll = JSON.parse(pg.disclose(evJson, new Uint8Array(K), marked, '[]', '{}', claim, false));
ok(dAll.disclosed.length === 16, 'disclose(indices []) -> all matched');
ok(throwsCode(() => pg.disclose(evJson, new Uint8Array(K), marked, '[-1]', '', claim, false), /^BadInput: /), 'disclose: bad indicesJson -> BadInput');
ok(throwsCode(() => pg.disclose(evJson, new Uint8Array(K), marked, 'null', '{"sourceClaim":1}', claim, false), /^BadInput: /), 'disclose: bad metaJson -> BadInput');
ok(throwsCode(() => pg.disclose(evJson, crypto.randomBytes(32), marked, 'null', '', claim, false), /^BadBlob: /), 'disclose with wrong K -> BadBlob');
ok(throwsCode(() => pg.disclose(evJson, new Uint8Array(K), input, '[0]', '', claim, false), /^BadDisclosure: /), 'disclose of an unmatched index without force -> BadDisclosure');
const dForce = pg.disclose(evJson, new Uint8Array(K), input, '[0]', '', claim, true);
ok(JSON.parse(dForce).disclosed.length === 1, 'disclose of an unmatched index with force -> allowed');
s = scanAll('disclose', secrets);
ok(s.K.full + s.K.win16 + s.K_d.full + s.K_d.win16 + s.K_blob.full + s.K_blob.win16 === 0, `memory scan after disclose: K ${s.K.full}/${s.K.win16}, K_d ${s.K_d.full}/${s.K_d.win16}, K_blob ${s.K_blob.full}/${s.K_blob.win16}`);

const vr = JSON.parse(pg.verifyDisclosure(dj, marked));
const pass = r => r.verdict.integrity_ok && r.verdict.all_reproduced; // same rule as norea-verify exit 0
ok(vr.schema === 'norea.disclosure-report.v1' && pass(vr) && vr.summary.matched === 16, 'verifyDisclosure(disclosure, marked) -> PASS, 16 reproduced');
const tampered = Buffer.from(marked); tampered[tampered.length - 2] ^= 1;
ok(!pass(JSON.parse(pg.verifyDisclosure(dj, tampered))), 'verifyDisclosure with 1 suspect byte changed -> FAIL');
ok(!pass(JSON.parse(pg.verifyDisclosure(dForce, input))), 'verifyDisclosure of a forced unmatched canary -> FAIL (not reproduced)');
const dBad = JSON.parse(dj); dBad.evidence.sig_b64 = (dBad.evidence.sig_b64[0] === 'A' ? 'B' : 'A') + dBad.evidence.sig_b64.slice(1);
ok(!pass(JSON.parse(pg.verifyDisclosure(JSON.stringify(dBad), marked))), 'verifyDisclosure with evidence signature changed -> FAIL');
ok(throwsCode(() => pg.verifyDisclosure('{', marked), /^BadDisclosure: /), 'verifyDisclosure(malformed) -> BadDisclosure');

// ---------------------------------------------------------------- 7. verifyEvidence, anchors
const v = JSON.parse(pg.verifyEvidence(evJson));
ok(v.signature_ok && v.evidence_id_ok && v.blob_hash_ok && v.has_anchors === false && v.anchors.length === 0,
  'verifyEvidence(valid) -> signature_ok, evidence_id_ok, blob_hash_ok, no anchors');
const back = JSON.parse(pg.verifyEvidence(JSON.stringify({ ...ev, created_claim: '2020-01-01T00:00:00Z' })));
ok(back.signature_ok === false && back.evidence_id_ok === false, 'verifyEvidence(backdated created_claim) -> signature_ok false');
ok(throwsCode(() => pg.verifyEvidence('[]'), /^BadEvidence: /), 'verifyEvidence(not an object) -> BadEvidence');
const subj = crypto.createHash('sha256').update(Buffer.concat([
  Buffer.from(['norea.evidence.v1', 'record.shape.v1', ev.dataset_id, ev.format, ev.original_sha256, ev.marked_sha256,
    String(ev.canary_count), ev.canary_root, JSON.stringify(ev.marker_fields), ev.canary_blob_sha256, ev.created_claim].join('\n')),
  Buffer.from([0x0a]), Buffer.from(ev.sig_b64, 'base64')])).digest('hex');
ok(pg.anchorSubjectHex(evJson) === subj, 'anchorSubjectHex == SHA-256(payload || 0x0A || sig) computed in JS');
ok(throwsCode(() => pg.anchorSubjectHex(JSON.stringify({ ...ev, sig_b64: '' })), /^BadEvidence: /), 'anchorSubjectHex(unsigned) -> BadEvidence');
ok(throwsCode(() => pg.tsaRequest(evJson, new Uint8Array(8)), /^ANCHOR_UNAVAILABLE: anchor not implemented until WP-08$/), 'tsaRequest -> ANCHOR_UNAVAILABLE (WP-08)');
ok(throwsCode(() => pg.attachAnchor(evJson, '{"kind":"rfc3161"}'), /^ANCHOR_UNAVAILABLE: anchor not implemented until WP-08$/), 'attachAnchor -> ANCHOR_UNAVAILABLE (WP-08)');

// ---------------------------------------------------------------- 8. small functions, errors
ok(pg.sha256Hex(input) === crypto.createHash('sha256').update(input).digest('hex'), 'sha256Hex == node crypto');
ok(throwsCode(() => pg.verifyingKey(new Uint8Array(31)), /^BadInput: seed must be exactly 32 bytes/), 'verifyingKey(31 B) -> BadInput');
ok(throwsCode(() => pg.protect(input, new Uint8Array(32), new Uint8Array(33), ds, '{"n":4}', claim), /^BadInput: seed/), 'protect(33-byte seed) -> BadInput');
ok(throwsCode(() => pg.protect(input, new Uint8Array(32), new Uint8Array(32), ds, '{"n":4}', 'yesterday'), /^BadInput: created_claim/), 'protect(bad created_claim) -> BadInput');
ok(throwsCode(() => pg.protect(input, new Uint8Array(32), new Uint8Array(32), ds, '{"n":4,"markerFields":["nope"]}', claim), /^(BadInput|NoMarker): /), 'protect(unknown marker field) -> error');
ok(throwsCode(() => pg.protect(te.encode('a,b\n1,2,3\n'), new Uint8Array(32), new Uint8Array(32), ds, '{"n":4}', claim), /^BadInput: /), 'protect(CSV column mismatch) -> BadInput');
const errs = [];
for (const f of [() => pg.inspect(input, 'x'), () => pg.check(marked, new Uint8Array(K), '{'), () => pg.tsaRequest('', new Uint8Array(0)),
  () => pg.disclose(evJson, new Uint8Array(K), input, '[0]', '', claim, false), () => pg.verifyDisclosure('{', marked)]) {
  try { f(); } catch (e) { errs.push(e.message); }
}
ok(errs.length === 5 && errs.every(m => CODE_RE.test(m)), 'every error message is "CODE: message" with a known CODE');
ok(errs.every(m => !m.includes(hexOf(K)) && !m.includes(hexOf(KD))), 'error messages contain no key hex');

const salt = crypto.randomBytes(16);
const t0 = performance.now();
const kek = pg.passphraseKek('correct horse battery staple', salt);
const argonMs = performance.now() - t0;
ok(kek.length === 32 && hexOf(kek) === hexOf(pg.passphraseKek('correct horse battery staple', salt)) &&
  hexOf(kek) !== hexOf(pg.passphraseKek('correct horse battery stapl', salt)), `passphraseKek -> 32 B, deterministic (Argon2id 64 MiB t=3: ${argonMs.toFixed(0)} ms)`);
ok(throwsCode(() => pg.passphraseKek('x', new Uint8Array(15)), /^BadInput: salt/), 'passphraseKek(15-byte salt) -> BadInput');
s = scanAll('passphraseKek x3', { K, seed: SEED, S: kek });
ok(s.K.full === 0 && s.seed.full === 0, 'memory scan after Argon2id (memory grown): K and seed still 0');
ok(s.S.full === 0 && s.S.win16 === 0, `memory scan: Argon2id output S (KEK input) ${s.S.full}/${s.S.win16} after JS copied it out`);
sr = stackResidue();
ok(sr < 1024, `stack region after passphraseKek: ${sr} non-zero bytes`);

// ---------------------------------------------------------------- 9. memory scan, vector keys (0x11 / 0x22 repeated: also catches byte-swapped copies)
s = scanAll('vector protect/check', { K: VK, seed: VSEED });
ok(s.K.full === 0 && s.seed.full === 0, `memory scan for vector K (0x11 x32) ${s.K.full} and seed (0x22 x32) ${s.seed.full}`);

// ---------------------------------------------------------------- 10. 50 000 rows (ARCHITECTURE §7)
const big = dataset(50000);
const K2 = crypto.randomBytes(32), S2 = crypto.randomBytes(32);
const time = (f, n = 3) => { const t = []; let r; for (let i = 0; i < n; i++) { const a = performance.now(); r = f(); t.push(performance.now() - a); } return { r, t }; };
const ti = time(() => JSON.parse(pg.inspect(big)));
const tp = time(() => { const x = pg.protect(big, new Uint8Array(K2), new Uint8Array(S2), 'perf', '{"n":64}', claim); const o = { m: x.marked, e: x.evidenceJson }; x.free(); return o; });
const tc = time(() => JSON.parse(pg.check(tp.r.m, new Uint8Array(K2), tp.r.e)));
const tv = time(() => JSON.parse(pg.verifyEvidence(tp.r.e)));
const fmt = r => r.t.map(x => x.toFixed(0)).join('/') + ' ms';
console.log(`      50k rows: input ${(big.length / 1e6).toFixed(2)} MB; inspect ${fmt(ti)}; protect n=64 ${fmt(tp)}; check ${fmt(tc)}; verifyEvidence ${fmt(tv)}`);
ok(ti.r.rows === 50000 && tc.r.matched === 64, `50k rows: inspect rows ${ti.r.rows}, check matched ${tc.r.matched}/64`);
s = scanAll('50k protect/check', { K: K2, seed: S2 });
ok(s.K.full === 0 && s.seed.full === 0, `memory scan after 50k run: K ${s.K.full}, seed ${s.seed.full}`);

// ---------------------------------------------------------------- 11. positive control: the scanner finds 32 B that took a non-secret path
// sha256Hex takes `&[u8]` and does not scrub the stack: SHA-256 leaves the message
// block on the shadow stack. The heap copy is wiped by the allocator on free.
const CTRL = crypto.randomBytes(32);
pg.sha256Hex(new Uint8Array(CTRL));
const c = scan(CTRL);
const at = Buffer.from(pg.__wasm.memory.buffer).indexOf(Buffer.from(CTRL));
ok(c.full >= 1, `positive control: 32 B passed to sha256Hex is found ${c.full} time(s) (first at ${at}, ${at < STACK_TOP ? 'stack' : 'heap'}), so the scan works`);
sr = stackResidue();
ok(sr > 1024, `positive control: stack region after an unscrubbed call has ${sr} non-zero bytes`);

console.log(`ALL SMOKE TESTS PASSED (${passed})`);
