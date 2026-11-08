// Integration test of the web platform contract (platform-web.js + custody.js)
// through the PASSPHRASE path, in node with an in-memory IndexedDB.
// Covered: key setup, AES-GCM wrap/unwrap, IndexedDB persistence, Argon2id KEK,
// protect/check through the contract, wrong passphrase, backup restore,
// registry (forbiddenAddrs) pass-through, input immutability.
// NOT covered here: WebAuthn PRF and the DOM (app.js). See tasks/todo.md P1-3.
//
// Run: node tests/platform.node.mjs <abs path to web/public>
import 'fake-indexeddb/auto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

// node's fetch cannot read file: URLs; wasm-bindgen's init() needs that for the .wasm.
const realFetch = globalThis.fetch;
globalThis.fetch = async u => {
  const url = new URL(u);
  if (url.protocol === 'file:') {
    return new Response(await readFile(url), { headers: { 'Content-Type': 'application/wasm' } });
  }
  return realFetch(u);
};
globalThis.window = globalThis;

const ok = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } console.log('ok  ', m); };
const throwsWith = async (fn, re) => { try { await fn(); return false; } catch (e) { return re.test(e.message); } };

const root = process.argv[2];
const platform = await import(pathToFileURL(`${root}/platform.js`).href);
await platform.ready();

const te = new TextEncoder(), td = new TextDecoder();
const PW = 'correct horse battery staple';
const ds = 'b2d_geo/parcels/2026-11';
const input = te.encode(JSON.stringify([
  { id: 'P-001', addr: '하남시 미사동 1-1', area_m2: 330.5 },
  { id: 'P-002', addr: '하남시 미사동 2-7', area_m2: 512.0 },
]));
const inputCopy = input.slice();

const missing = platform.CONTRACT.filter(f => typeof platform[f] !== 'function');
ok(missing.length === 0, `platform exports the full contract (${platform.CONTRACT.length} functions)${missing.length ? ' missing: ' + missing : ''}`);
ok(!(await platform.hasKey()) && (await platform.keyInfo()) === null, 'fresh state: no key');

const backup = await platform.setupKey({ passphrase: PW });
const info = await platform.keyInfo();
ok(info?.method === 'passphrase' && /^[0-9a-f]{16}$/.test(info.fingerprint), `setupKey -> passphrase key, fingerprint ${info?.fingerprint}`);
ok(info.hardwareDuringSigning === false, 'web reports hardwareDuringSigning=false (ADR-006 honesty)');
const bj = JSON.parse(td.decode(backup));
ok(bj.format === 'norea.custody-backup.v1' && bj.ct && !('seed' in bj) && !('masterK' in bj), 'backup is encrypted blob only, no plaintext secrets');

const { marked, evidenceJson } = await platform.protect({ input, datasetId: ds, n: 16, passphrase: PW });
ok(input.every((b, i) => b === inputCopy[i]) && input.length === inputCopy.length, 'protect did not modify the input bytes');
const rows = JSON.parse(td.decode(marked));
ok(rows.length === 18, 'protect -> valid JSON, 2 + 16 rows');
ok(platform.verifyEvidence(evidenceJson) === true, 'verifyEvidence needs no secrets and passes');

const rep = await platform.check({ suspect: marked, evidenceJson, passphrase: PW });
ok(rep.matched === 16 && rep.canary_commit_ok && rep.evidence_signature_ok, `check(marked) -> ${rep.matched}/${rep.total}`);

ok(await throwsWith(() => platform.check({ suspect: marked, evidenceJson, passphrase: 'wrong' }), /복호화 실패/), 'wrong passphrase -> rejected');
ok(await throwsWith(() => platform.protect({ input, datasetId: ds, n: 16 }), /패스프레이즈/), 'missing passphrase -> rejected');

// Registry pass-through: forbid every canary address from the first run.
const origAddrs = new Set(JSON.parse(td.decode(input)).map(r => r.addr));
const canaryAddrs = rows.map(r => r.addr).filter(a => !origAddrs.has(a));
const second = await platform.protect({ input, datasetId: ds, n: 16, forbiddenAddrs: canaryAddrs, passphrase: PW });
const secondAddrs = JSON.parse(td.decode(second.marked)).map(r => r.addr);
ok(canaryAddrs.length === 16 && !secondAddrs.some(a => canaryAddrs.includes(a)), 'forbiddenAddrs respected: no forbidden address reused');

// "New device": overwrite with a different key, then restore the backup.
await platform.setupKey({ passphrase: 'another passphrase' });
ok((await platform.keyInfo()).fingerprint !== info.fingerprint, 'second setup created a different key');
await platform.importBackup(backup);
ok((await platform.keyInfo()).fingerprint === info.fingerprint, 'importBackup restored the original key');
const rep2 = await platform.check({ suspect: marked, evidenceJson, passphrase: PW });
ok(rep2.matched === 16, 'restored key still opens old evidence');

console.log('ALL PLATFORM CONTRACT TESTS PASSED');
