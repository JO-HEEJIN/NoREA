// Key custody for the browser build.
//
// Secrets: master key K (32 B) + ML-DSA seed (32 B) = 64 B, wrapped with
// AES-256-GCM under a key-encryption key (KEK). The KEK comes from:
//   1. WebAuthn PRF (preferred): a hardware-backed secret released only after
//      user verification (Face ID / Touch ID / Windows Hello / phone).
//      Used purely as a local KDF. There is no server and no login here.
//   2. Argon2id(passphrase) fallback, computed in WASM, when PRF is missing.
// The wrapped blob lives in IndexedDB. Nothing secret leaves the browser.
//
// Honest limit: while signing, the unwrapped seed is in page memory. PRF
// protects the key at rest, not in use. See ADR-006.

import * as pg from './pkg/norea_web.js';

const DB = 'norea', STORE = 'custody', KEY = 'v1';
const te = new TextEncoder();
const PRF_SALT = te.encode('norea/prf/v1');   // fixed: same passkey -> same PRF output
const HKDF_INFO = te.encode('norea/kek/v1');
const AAD = te.encode('norea/custody/v1');    // binds ciphertext to purpose + version

// ---------------------------------------------------------------- storage
let dbPromise = null; // one cached connection instead of one per operation
function idb() {
  dbPromise ??= new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => {
      const db = r.result;
      db.onversionchange = () => { db.close(); dbPromise = null; };
      res(db);
    };
    r.onerror = () => { dbPromise = null; rej(r.error); };
  });
  return dbPromise;
}
async function tx(mode, fn) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, mode);
    const out = fn(t.objectStore(STORE));
    t.oncomplete = () => res(out.result);
    t.onerror = () => rej(t.error);
  });
}
const load = () => tx('readonly', s => s.get(KEY));
const save = rec => tx('readwrite', s => s.put(rec, KEY));

export async function hasCustody() { return !!(await load()); }

/** Ask the browser not to evict our storage (Safari evicts script-writable
 *  storage of sites not visited for a while). Backup export is still mandatory. */
export async function requestPersistence() {
  try { return (await navigator.storage?.persist?.()) === true; } catch { return false; }
}

// ---------------------------------------------------------------- KEK
async function kekFrom(secret32) {
  const base = await crypto.subtle.importKey('raw', secret32, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: HKDF_INFO },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function prfAvailable() {
  if (!window.PublicKeyCredential) return false;
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps && 'extension:prf' in caps) return !!caps['extension:prf'];
  } catch { /* unknown: try it and fall back on failure */ }
  return true;
}

async function prfEval(credId) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [{ type: 'public-key', id: credId }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: PRF_SALT } } },
  }});
  const out = a.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('이 인증기는 PRF 값을 돌려주지 않았습니다. 패스프레이즈 방식을 쓰세요.');
  return new Uint8Array(out);
}

async function createPrfPasskey() {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'NoREA' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'norea', displayName: 'NoREA 서명키' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    extensions: { prf: { eval: { first: PRF_SALT } } },
  }});
  const ext = cred.getClientExtensionResults();
  if (!ext.prf?.enabled) throw new Error('이 인증기는 PRF를 지원하지 않습니다.');
  const credId = new Uint8Array(cred.rawId);
  // Some authenticators return PRF output at creation, most need a get().
  const first = ext.prf.results?.first;
  return { credId, prf: first ? new Uint8Array(first) : await prfEval(credId) };
}

// ---------------------------------------------------------------- public API
/** Create K + seed, wrap them, store. Returns the public verifying key. */
export async function setup({ passphrase } = {}) {
  const secrets = crypto.getRandomValues(new Uint8Array(64)); // [0,32)=K  [32,64)=seed
  try {
    let rec, raw;
    if (passphrase) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      raw = pg.passphraseKek(passphrase, salt);
      rec = { v: 1, method: 'passphrase', kdf: { alg: 'argon2id', m: 65536, t: 3, p: 1 }, salt };
    } else {
      const { credId, prf } = await createPrfPasskey();
      raw = prf;
      rec = { v: 1, method: 'prf', credId };
    }
    const kek = await kekFrom(raw); raw.fill(0);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    rec.iv = iv;
    rec.ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, kek, secrets));
    rec.vk = pg.verifyingKey(secrets.subarray(32, 64));
    await save(rec);
    await requestPersistence();
    return { vk: rec.vk };
  } finally {
    secrets.fill(0);
  }
}

/** Unwrap secrets, run fn, then zero them no matter what. */
export async function withSecrets(fn, { passphrase } = {}) {
  const rec = await load();
  if (!rec) throw new Error('먼저 서명키를 만드세요.');
  let raw;
  if (rec.method === 'prf') raw = await prfEval(rec.credId);
  else {
    if (!passphrase) throw new Error('패스프레이즈가 필요합니다.');
    raw = pg.passphraseKek(passphrase, rec.salt);
  }
  const kek = await kekFrom(raw); raw.fill(0);
  let secrets;
  try {
    secrets = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: AAD }, kek, rec.ct));
  } catch {
    throw new Error('복호화 실패: 잘못된 패스프레이즈이거나 다른 패스키입니다.');
  }
  try {
    return await fn({ masterK: secrets.subarray(0, 32), seed: secrets.subarray(32, 64) });
  } finally {
    secrets.fill(0);
  }
}

export async function publicKey() { return (await load())?.vk ?? null; }
export async function method() { return (await load())?.method ?? null; }

const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const BIN = ['credId', 'salt', 'iv', 'ct', 'vk'];

/** Encrypted backup. Safe to store anywhere: useless without the passkey or passphrase. */
export async function exportBackup() {
  const rec = await load();
  if (!rec) throw new Error('백업할 키가 없습니다.');
  const out = { ...rec };
  for (const k of BIN) if (out[k]) out[k] = b64(out[k]);
  return te.encode(JSON.stringify({ format: 'norea.custody-backup.v1', ...out }));
}

export async function importBackup(bytes) {
  const j = JSON.parse(new TextDecoder().decode(bytes));
  if (j.format !== 'norea.custody-backup.v1') throw new Error('백업 파일 형식이 아닙니다.');
  delete j.format;
  for (const k of BIN) if (j[k]) j[k] = unb64(j[k]);
  await save(j);
}
