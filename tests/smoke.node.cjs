// End-to-end smoke test of the exact WASM API the browser uses.
// Run: node tests/smoke.node.cjs <path-to-nodejs-bindings>
const pg = require(process.argv[2] || '/tmp/pg-node/norea_web.js');
const crypto = require('node:crypto');
const enc = new TextEncoder();
const assert = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } console.log('ok  ', m); };

const master = crypto.randomBytes(32), seed = crypto.randomBytes(32);
const ds = 'b2d_geo/parcels/2026-11';
const original = enc.encode(JSON.stringify([
  { id: 'P-001', addr: '하남시 미사동 1-1', area_m2: 330.5 },
  { id: 'P-002', addr: '하남시 미사동 2-7', area_m2: 512.0 },
]));

const kd = pg.deriveDatasetKey(master, ds);
assert(kd.length === 32, 'deriveDatasetKey -> 32 bytes');

const m = pg.markParcels(original, kd, 16, '[]');
const rows = JSON.parse(new TextDecoder().decode(m.bytes));
assert(rows.length === 18 && m.attempts.length === 16, 'markParcels -> valid JSON, 2 + 16 rows');

const vk = pg.verifyingKey(seed);
assert(vk.length === 1952, 'verifyingKey -> 1952 bytes (ML-DSA-65)');

const evJson = pg.buildEvidence(m.bytes, m.attempts, ds, kd, new Date().toISOString(), seed);
const ev = JSON.parse(evJson);
assert(ev.schema === 'norea.evidence.v1' && ev.canary_kind === 'b2d_geo.parcel.v1', 'buildEvidence -> schema + kind');
assert(Buffer.from(ev.sig_b64, 'base64').length === 3309, 'signature is 3309 bytes');
assert(pg.verifyEvidence(evJson) === true, 'verifyEvidence(valid) -> true');

const tampered = JSON.stringify({ ...ev, created_claim: '2020-01-01T00:00:00Z' });
assert(pg.verifyEvidence(tampered) === false, 'verifyEvidence(backdated) -> false');

// A "regenerated" copy: renamed keys, reversed order, area as string, nested.
const copy = enc.encode(JSON.stringify({ items: rows.slice().reverse().map(r => ({
  name: r.id, where: r.addr, sqm: String(r.area_m2) })) }));
const rep = JSON.parse(pg.checkCopy(copy, kd, evJson));
assert(rep.matched === 16 && rep.total === 16, `checkCopy(regenerated copy) -> ${rep.matched}/${rep.total}`);
assert(rep.evidence_signature_ok && rep.canary_commit_ok, 'report: signature ok, commit ok');

const wrongKd = pg.deriveDatasetKey(crypto.randomBytes(32), ds);
const rep2 = JSON.parse(pg.checkCopy(copy, wrongKd, evJson));
assert(rep2.matched === 0 && rep2.canary_commit_ok === false, 'wrong key -> 0 matched, commit flagged');

const clean = JSON.parse(pg.checkCopy(original, kd, evJson));
assert(clean.matched === 0, 'unrelated data -> 0 matched');

let threw = false; try { pg.buildEvidence(m.bytes, m.attempts, ds, kd, 'x', new Uint8Array(31)); } catch { threw = true; }
assert(threw, 'bad seed length -> throws');

const t0 = performance.now();
const kek = pg.passphraseKek('correct horse battery staple', crypto.randomBytes(16));
const ms = (performance.now() - t0).toFixed(0);
assert(kek.length === 32, `passphraseKek (Argon2id 64MiB t3) -> 32 bytes in ${ms} ms`);

const big = enc.encode(JSON.stringify(Array.from({ length: 50000 }, (_, i) =>
  ({ id: `R-${i}`, addr: `서울시 테스트동 ${i}`, area_m2: 100 + i / 100 }))));
const t1 = performance.now();
const mb = pg.markParcels(big, kd, 64, '[]');
const ev2 = pg.buildEvidence(mb.bytes, mb.attempts, ds, kd, new Date().toISOString(), seed);
const r3 = JSON.parse(pg.checkCopy(mb.bytes, kd, ev2));
const ms2 = (performance.now() - t1).toFixed(0);
assert(r3.matched === 64, `50k-row dataset (${(big.length/1e6).toFixed(1)} MB): mark 64 + sign + check in ${ms2} ms`);
console.log('ALL SMOKE TESTS PASSED');
