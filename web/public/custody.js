// Web key custody, norea.custody-backup.v1 (Fable_5_1/docs/protocol/custody-web-v1.md).
//
// secrets = K (32 B) || seed (32 B), from crypto.getRandomValues (WASM has no RNG).
// KEK     = HKDF-SHA256(salt = 32 x 0x00, ikm = S, info = "norea/kek/v1"), AES-256-GCM key
//           S = WebAuthn PRF output (method "prf") or Argon2id(passphrase) from WASM
//           passphraseKek (method "passphrase", m = 64 MiB, t = 3, p = 1).
// blob    = AES-256-GCM(KEK, iv 12 B random, AAD = "norea/custody/v1", secrets) -> IndexedDB.
// PRF is a local KDF only. There is no server and no login.
//
// Secret handling (platform-contract "secret handling rules (web)"): withSecrets() unwraps,
// hands K and seed to exactly one WASM call, and fills the buffer with 0 in finally.
// S is filled with 0 right after the KEK is derived. The KEK is a non-extractable
// CryptoKey. A passphrase is a JS string and cannot be wiped (ADR-0006).
// Nothing here logs, and no error message carries a secret.
//
// Honest limit: while signing, the seed is in page memory (hardwareDuringSigning: false).

import * as wasm from './pkg/norea_web.js';

const DB = 'norea', STORE = 'custody', KEY = 'v1';
export const BACKUP_FORMAT = 'norea.custody-backup.v1';
const te = new TextEncoder();
const PRF_SALT = te.encode('norea/prf/v1');   // same passkey -> same PRF output
const HKDF_INFO = te.encode('norea/kek/v1');
const AAD = te.encode('norea/custody/v1');
const KDF = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 }); // what passphraseKek computes
const IV_LEN = 12, CT_LEN = 64 + 16, VK_LEN = 1952;

/**
 * Error with a platform-contract code: KEY_MISSING, KEY_EXISTS, BAD_PASSPHRASE,
 * PRF_UNSUPPORTED, CANCELLED or BACKUP_INVALID.
 */
export function custodyError(code, message) {
  const e = new Error(message);
  e.code = code;
  e.platform = true;
  return e;
}

/** created_claim / createdClaim: exactly 20 chars, RFC 3339 UTC (evidence-v1 §5). A claim, not a time proof. */
export const claimNow = () => new Date().toISOString().slice(0, 19) + 'Z';
const CLAIM_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ---------------------------------------------------------------- storage
let dbPromise = null; // one cached connection
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
    const req = fn(t.objectStore(STORE));
    t.oncomplete = () => res(req.result);
    t.onerror = () => rej(t.error);
    t.onabort = () => rej(t.error);
  });
}
const load = () => tx('readonly', s => s.get(KEY));
const save = rec => tx('readwrite', s => s.put(rec, KEY));

export async function hasCustody() { return !!(await load()); }

/** Public part of the record: `{method, vk, createdClaim}` or null. */
export async function info() {
  const rec = await load();
  return rec ? { method: rec.method, vk: rec.vk, createdClaim: rec.createdClaim ?? null } : null;
}

export async function remove() { await tx('readwrite', s => s.delete(KEY)); persistedResult = null; }

// §2: the persist() result lives outside the record (here: memory for this page).
let persistedResult = null;

/** Ask the browser not to evict the store (§2). true | false | "unknown" (no StorageManager). */
export async function requestPersistence() {
  try {
    const persist = globalThis.navigator?.storage?.persist;
    persistedResult = typeof persist === 'function' ? (await globalThis.navigator.storage.persist()) === true : 'unknown';
  } catch { persistedResult = 'unknown'; }
  return persistedResult;
}

/**
 * keyInfo().persisted: the result of this page's persist() request if there was
 * one, else the browser's current state (`persisted()`, no prompt), else "unknown".
 */
export async function persistedState() {
  if (persistedResult !== null) return persistedResult;
  try {
    const persisted = globalThis.navigator?.storage?.persisted;
    if (typeof persisted === 'function') return (await globalThis.navigator.storage.persisted()) === true;
  } catch { /* fall through */ }
  return 'unknown';
}

// ---------------------------------------------------------------- KEK
async function kekFrom(s32) {
  try {
    const base = await crypto.subtle.importKey('raw', s32, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: HKDF_INFO },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    s32.fill(0);
  }
}

/** true | false | "unknown" (§4). "unknown": try PRF and fall back to a passphrase on failure. */
export async function prfAvailable() {
  const PKC = globalThis.PublicKeyCredential;
  if (!PKC) return false;
  if (typeof PKC.getClientCapabilities !== 'function') return 'unknown';
  try {
    const caps = await PKC.getClientCapabilities();
    if (caps && typeof caps['extension:prf'] === 'boolean') return caps['extension:prf'];
  } catch { /* fall through */ }
  return 'unknown';
}

const passkeyCancelled = () => custodyError('CANCELLED', 'The passkey prompt was cancelled or did not complete.');
const noWebAuthn = () => custodyError('PRF_UNSUPPORTED', 'passkey (WebAuthn) is not available in this browser. Use a passphrase instead.');
const hasWebAuthn = () => typeof globalThis.navigator?.credentials?.create === 'function' && !!globalThis.PublicKeyCredential;

async function prfEval(credId) {
  if (!hasWebAuthn()) throw noWebAuthn();
  let a;
  try {
    a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    } });
  } catch { throw passkeyCancelled(); }
  const out = a?.getClientExtensionResults?.().prf?.results?.first;
  if (!out) throw custodyError('PRF_UNSUPPORTED', 'This passkey did not return a PRF value. Restore from a passphrase backup.');
  return new Uint8Array(out);
}

async function createPrfPasskey() {
  if (!hasWebAuthn()) throw noWebAuthn();
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      rp: { name: 'NoREA' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'norea', displayName: 'NoREA signing key' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    } });
  } catch { throw passkeyCancelled(); }
  const ext = cred.getClientExtensionResults();
  if (!ext.prf?.enabled) {
    // §4: the credential just created is orphaned; the web cannot delete it.
    throw custodyError('PRF_UNSUPPORTED', 'This authenticator does not support PRF. The passkey just created is left unused on the device (a web page cannot delete it). Create the key again with a passphrase.');
  }
  const credId = new Uint8Array(cred.rawId);
  const first = ext.prf.results?.first; // some authenticators return it at creation, most need a get()
  return { credId, prf: first ? new Uint8Array(first) : await prfEval(credId) };
}

// ---------------------------------------------------------------- setup / use
/** Create K + seed, wrap, store. Refuses if a key exists (UI: confirmAction, then deleteKey). */
export async function setup({ passphrase } = {}) {
  if (await load()) throw custodyError('KEY_EXISTS', 'A signing key already exists. Check your backup first, then delete the existing key.');
  if (passphrase !== undefined && passphrase !== null && typeof passphrase !== 'string') {
    throw custodyError('BAD_PASSPHRASE', 'The passphrase must be a string.');
  }
  const secrets = crypto.getRandomValues(new Uint8Array(64)); // [0,32) = K, [32,64) = seed
  try {
    let rec, s;
    if (passphrase) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      s = wasm.passphraseKek(passphrase, salt);
      rec = { v: 1, method: 'passphrase', salt, kdf: { ...KDF } };
    } else {
      const { credId, prf } = await createPrfPasskey();
      s = prf;
      rec = { v: 1, method: 'prf', credId };
    }
    const kek = await kekFrom(s);
    rec.iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    rec.ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: AAD }, kek, secrets));
    rec.vk = wasm.verifyingKey(secrets.subarray(32, 64)); // the seed's one crossing in setup
    rec.createdClaim = claimNow();
    await save(rec);
    await requestPersistence();
    return { vk: rec.vk };
  } finally {
    secrets.fill(0);
  }
}

/**
 * §4: load record -> S -> KEK -> decrypt -> fn(K, seed) -> fill(0) in finally.
 * `fn` must hand K and seed to exactly one WASM call.
 */
export async function withSecrets(fn, { passphrase } = {}) {
  const rec = await load();
  if (!rec) throw custodyError('KEY_MISSING', 'No signing key. Create one first or restore it from a backup.');
  let s;
  if (rec.method === 'prf') {
    s = await prfEval(rec.credId);
  } else {
    if (typeof passphrase !== 'string' || passphrase.length === 0) throw custodyError('BAD_PASSPHRASE', 'A passphrase is required.');
    const k = rec.kdf;
    if (k.alg !== KDF.alg || k.m !== KDF.m || k.t !== KDF.t || k.p !== KDF.p) {
      throw custodyError('BACKUP_INVALID', 'This version cannot open a key with these Argon2id parameters.');
    }
    s = wasm.passphraseKek(passphrase, rec.salt);
  }
  const kek = await kekFrom(s);
  let secrets;
  try {
    secrets = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: AAD }, kek, rec.ct));
  } catch {
    throw custodyError('BAD_PASSPHRASE', 'Cannot unlock the key. Wrong passphrase or a different passkey.');
  }
  try {
    return await fn(secrets.subarray(0, 32), secrets.subarray(32, 64));
  } finally {
    secrets.fill(0);
  }
}

// ---------------------------------------------------------------- backup (§3)
function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}
const invalid = what => custodyError('BACKUP_INVALID', `Invalid backup file: ${what}`);
function unb64(s, what) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw invalid(`${what} must be base64.`);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
const intIn = (x, lo, hi) => Number.isInteger(x) && x >= lo && x <= hi;

/** Encrypted blob only. Useless without the passkey or the passphrase. */
export async function exportBackup() {
  const rec = await load();
  if (!rec) throw custodyError('KEY_MISSING', 'There is no signing key to back up.');
  const out = { format: BACKUP_FORMAT, v: 1, method: rec.method };
  if (rec.method === 'prf') out.credId = b64(rec.credId);
  else { out.kdf = { ...rec.kdf }; out.salt = b64(rec.salt); }
  out.iv = b64(rec.iv);
  out.ct = b64(rec.ct);
  out.vk = b64(rec.vk);
  if (rec.createdClaim) out.createdClaim = rec.createdClaim;
  return te.encode(JSON.stringify(out));
}

/** §3 import checks. Returns a clean IndexedDB record; unknown keys are dropped. */
export function parseBackup(bytes) {
  if (!(bytes instanceof Uint8Array)) throw invalid('not bytes (Uint8Array).');
  let j;
  try { j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw invalid('not JSON.'); }
  if (!j || typeof j !== 'object' || Array.isArray(j)) throw invalid('not a JSON object.');
  if (j.format !== BACKUP_FORMAT) throw invalid(`format is not ${BACKUP_FORMAT}.`);
  if (j.v !== 1) throw invalid('v is not 1.');
  if (j.method !== 'prf' && j.method !== 'passphrase') throw invalid('unknown method.');
  const rec = { v: 1, method: j.method };
  if (j.method === 'prf') {
    rec.credId = unb64(j.credId, 'credId');
    if (rec.credId.length < 16 || rec.credId.length > 1023) throw invalid('credId length is not 16..1023 B.');
  } else {
    rec.salt = unb64(j.salt, 'salt');
    if (rec.salt.length < 16 || rec.salt.length > 64) throw invalid('salt length is not 16..64 B.');
    const k = j.kdf;
    if (!k || typeof k !== 'object' || k.alg !== 'argon2id') throw invalid('kdf.alg is not argon2id.');
    if (!intIn(k.m, 8192, 1048576)) throw invalid('kdf.m is outside 8192..1048576.');
    if (!intIn(k.t, 1, 10)) throw invalid('kdf.t is outside 1..10.');
    if (k.p !== 1) throw invalid('kdf.p is not 1.');
    rec.kdf = { alg: 'argon2id', m: k.m, t: k.t, p: 1 };
  }
  rec.iv = unb64(j.iv, 'iv');
  if (rec.iv.length !== IV_LEN) throw invalid('iv is not 12 B.');
  rec.ct = unb64(j.ct, 'ct');
  if (rec.ct.length !== CT_LEN) throw invalid('ct is not 80 B.');
  rec.vk = unb64(j.vk, 'vk');
  if (rec.vk.length !== VK_LEN) throw invalid('vk is not 1952 B.');
  // createdClaim is not an import condition (§3); kept only when well formed.
  if (typeof j.createdClaim === 'string' && CLAIM_RE.test(j.createdClaim)) rec.createdClaim = j.createdClaim;
  return rec;
}

/** Validate, then store (overwrites: the UI asks confirmAction first when a key exists). */
export async function importBackup(bytes) {
  await save(parseBackup(bytes));
  await requestPersistence(); // §2: after every store write
}
