# NoREA design, in English

The real design package is in `docs/design/`, in Korean, written on 2026-11-08. This is the short version for people who don't read Korean and have ten minutes. If the two disagree, the Korean protocol specs win, and `CONTEXT.md` says what the code does today.

## The idea

Copying can't be stopped. Bot walls lose, and they hurt real users. So we don't try. We plant fake but plausible records (canaries) in the owner's own public table, sign a commitment to them, and later show that a suspect copy contains them. The algorithm is public. The key is secret. Kerckhoffs would be fine with it.

## Architecture

Four pieces.

`core/` (`noreacore`) is pure Rust. Parsing, shape inference, canary generation and insertion, evidence prepare/finalize/verify, Merkle, blob encryption, check, disclose, disclosure verify, TSA request encode and response parse. It has no RNG, no network, no file I/O, no key storage and no clock. Time and nonces come in as arguments. Public functions take and return bytes and JSON strings, so they map 1:1 onto wasm-bindgen, Tauri commands or UniFFI.

Signing goes through a seam: `prepare_evidence` builds the payload, the platform signs it, `finalize_evidence` verifies the signature before accepting it. A broken adapter can't produce evidence. It just fails. The browser wasm dependency tree has zero `getrandom`, and `scripts/test.sh` checks that.

`web/` (`norea-web`) is wasm-bindgen bindings, type conversion only. `web/public/` is a static app with no server, no CDN, no external scripts or fonts, and a strict CSP. The UI (`app.js`) only calls the platform contract (`platform.js`). It never touches WASM or key storage directly.

`cli/` has `norea-verify`, the third-party verifier (offline, no secrets), and `norea`, the dev and test CLI.

Trust boundary: in the web app, data, canaries and keys never leave the browser. The only planned outbound call is a time anchor, and the only thing that would leave is a 32-byte hash. Today the anchor exists in the CLI only.

## The five frozen protocols

Frozen means: change it and every evidence already issued stops verifying. So we don't. A change means a new version name. Vector tests guard this.

**Evidence v1 (`norea.evidence.v1`).** The signing payload is 11 lines of UTF-8 separated by `\n`, no trailing newline: schema, canary_kind, dataset_id, format, original_sha256, marked_sha256, canary_count, canary_root, marker fields (compact JSON), canary_blob_sha256, created_claim. No JSON canonicalization in the payload, on purpose: Swift or Kotlin should be able to rebuild it with string concatenation. Signature is ML-DSA-65 (FIPS 204) with context string `norea/evidence/v1`, so a signature from this key can't be replayed into another protocol. `canary_root` is a Merkle root with the RFC 9162 structure, leaf = `SHA-256(0x00 || u32be(i) || canon(row))`. The canaries themselves ride along in the evidence, encrypted with ChaCha20-Poly1305 under `K_blob = HKDF(K_d, marked_sha256)`. K_blob is unique per evidence, so the nonce is fixed at zero. Time anchors live outside the payload and commit to `anchor_subject = SHA-256(payload || 0x0A || sig)`, so you can't re-sign with another key and borrow someone's anchor.

**Canary generator (`record.shape.v1`).** Learn each field's shape from the input, then draw fake rows that fit it. NUMERIC fields use gap sampling: pick a gap between two adjacent real values and draw an integer inside it. STRING fields become templates (runs of character classes like `D3`, `H2`); a template is drawn in proportion to its count, the letter slots are copied from a real "anchor" value whose vocabulary appears at least twice, and digit slots are drawn inside the observed range. Categories are drawn by frequency. All draws are HMAC under the dataset key K_d, so the same input, key and options give the same canaries and the same marked bytes on every platform. Collision avoidance: if a marker or unique field value equals a real value, an operator exclusion (an official registry, checked locally), or an earlier canary, retry, up to 64 times, then fail with `CanaryExhausted`. Acceptance test for distinguishability: a classifier trying to tell canaries from real rows must stay under AUC 0.60. We measured 0.516 / 0.506 / 0.491 on real data. Logic for an existing `canary_kind` never changes; new behavior means a new kind.

**Disclosure v1 (`norea.disclosure.v1`).** What you hand a court expert: the full evidence, the suspect copy's hash, and only the matched canaries, each with its Merkle audit path. Unmatched canaries stay secret (disclosing them needs a force flag). The verifier checks signature, evidence_id, blob hash, anchor imprints, Merkle paths, and that every disclosed canary reproduces in the copy. Verdict: PASS (exit 0) only if integrity holds (signature, ids, hashes, at least one disclosed canary, all Merkle paths good, no checked anchor with a wrong imprint) and every disclosed canary reproduces. Otherwise FAIL (exit 1). Malformed input is exit 2. The statement includes a model upper bound on a chance match:

```
X = (sum of the t smallest space_log2 among the m markers) - log2 C(m, t)
P(one canary matches one independent record by chance) <= 2^-X
expected chance matches <= n * R * 2^-X     (n canaries, R records in the copy)
```

That is a bound under our generator model, not a real-world probability, and the statement says so.

**Web custody v1 (`norea.custody-backup.v1`).** Secrets are K (32 B) and the signing seed (32 B). They are wrapped with a KEK from HKDF over either a WebAuthn PRF output (same passkey, same output) or Argon2id of a passphrase (64 MiB, t = 3, p = 1), then AES-256-GCM. The record sits in IndexedDB with no plaintext secret anywhere. A backup download is forced right after key creation. The backup file is the same encrypted blob in JSON. A PRF backup only opens on a device with the same passkey, so we suggest a second passphrase backup. Nothing goes in localStorage, URLs, logs or error messages.

**Platform contract.** 17 functions the UI is allowed to call: ready, capabilities, hasKey, keyInfo, setupKey, deleteKey, exportBackup, importBackup, inspect, protect, anchor, check, disclose, verifyEvidence, verifyDisclosure, saveFile, confirmAction. 12 error codes: `KEY_MISSING`, `KEY_EXISTS`, `BAD_PASSPHRASE`, `PRF_UNSUPPORTED`, `CANCELLED`, `BAD_INPUT`, `NO_MARKER`, `CANARY_EXHAUSTED`, `BAD_EVIDENCE`, `BAD_DISCLOSURE`, `ANCHOR_UNAVAILABLE`, `BACKUP_INVALID`. Swap `platform.js` for a Tauri implementation and the same UI runs as a desktop or mobile app.

## Threat model, short

The copier can:
- copy verbatim, re-serialize (rename keys, reorder, nest, CSV to JSON, render to HTML), or drop a field. We still match: value-based, normalized, marker k-of-n.
- try simple statistical filtering. Canaries follow the field shapes, so pattern filters don't find them (AUC target < 0.60).
- learn canaries from a past disclosure. We disclose as few as possible. Disclosed canaries are burned.
- claim "we got it from the same public source". `original_sha256` shows those rows were not in the original.

The copier can also beat us, and we say so:
- check every row against an official registry and drop the fakes. If they pay that cost, canaries lose. We will not use real addresses to dodge this.
- drop every marker field, or regenerate the whole dataset. Nothing left to find.
- filter on cross-field correlation. v1 doesn't model it.

A dishonest operator can't backdate (only anchors prove time), can't add canaries after seeing the other side's data (root is fixed in the signature and anchor), can't reuse an anchor with a new key, and can't swap the blob. They can fake the suspect copy itself. We don't prove how a copy was captured; those fields are `*_claim` and we recommend outside evidence like a notary or an archive.

Outside attackers: web hosting compromise is mitigated (same-origin only, CSP, published wasm hash) but hosting still has to be trusted; high assurance means the desktop app. A stolen device gives an encrypted blob that needs the passkey or passphrase. On web, Windows and Android the key is in memory while signing, and the UI says so.

## Key decisions (the 14 ADRs)

1. **Prove, don't block.** We make third-party-verifiable evidence of copying instead of trying to stop it.
2. **Canaries are fake records learned from the data's own shape.** Hardcoded patterns got filtered, so the generator infers templates and distributions per field.
3. **ML-DSA-65 with FIPS 204 context `norea/evidence/v1`.** Evidence has to survive the post-quantum deprecation of RSA and ECDSA.
4. **Time is proven only by external anchors, and anchors bind the signature.** A local clock proves nothing, and anchoring only the content hash allowed anchor reuse.
5. **Pure core with a signing seam.** No RNG, network, I/O, key storage or clock in core, so every platform shares one verified implementation.
6. **Key custody per platform, with hardware honesty.** We never claim the key stays in hardware on platforms where it sits in memory during signing.
7. **Web first, same UI reused in Tauri 2.** One static app now; desktop and mobile later by swapping one platform file.
8. **Evidence v1 uses a Merkle commitment, an encrypted blob, and a freeze policy.** Selective disclosure needs Merkle paths, and check shouldn't need the original data.
9. **Web trust model.** No external scripts, strict CSP, published wasm hash, forced encrypted backup.
10. **Fresh start, no ProvGuard compatibility.** The predecessor format was never shipped and had design flaws, so we started the `norea.*` namespace clean.
11. **Third-party verification without secrets, using only disclosed canaries.** Evidence is only worth something if the other side can check it without trusting us.
12. **Secrets cross the WASM boundary once and get zeroed on both sides.** The old web code copied keys across three times and left copies in wasm memory.
13. **Inputs are JSON arrays and CSV.** JSON is re-serialized; CSV keeps original bytes and splices canary records in between.
14. **WASM bindings zero every freed heap block and scrub the stack after secret calls.** A memory scan found key bytes that per-variable zeroize couldn't reach.

## Measured limits

- AUC 0.516 / 0.506 / 0.491 on the real 20,561-row MOLIT legal-dong file. Coin flip is 0.5.
- protect, 50k rows, 64 canaries, signing included: 0.44 s in WASM under node 22. Not measured in a real browser tab.
- check, 50k rows: about 94 ms for JSON, native.
- False matches: 0/128 on independent data.
- wasm is 782 KB against a 600 KB target.
- No defense against full rewrite clones, cross-field correlation analysis, or EAV restructuring. Dense sequential keys can't hold canaries.
- TSA anchors via CLI only. TSA chain verification is a manual openssl step. No OpenTimestamps, no relay, no web anchor button yet.

## Where to look

- `docs/design/ARCHITECTURE.md`, `THREAT-MODEL.md`, `CORE-API.md`, `SOURCES.md`: originals, in Korean.
- `docs/design/protocol/`: the five frozen specs. Normative.
- `docs/design/adr/`: the 14 ADRs.
- `tests/vectors/`: the frozen vectors.
