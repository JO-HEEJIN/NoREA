# NoREA

We don't block scrapers. Nobody can. So we leave fingerprints in your data and prove the copy later.

NoREA lets a data owner plant fake but plausible records (canaries) in their own public table, sign evidence of it with ML-DSA-65, check a suspect copy the owner brings in, and hand a third party a disclosure they can verify with no secrets at all.

The name is a nod to REA, "Reverse Engineer Anything" (github.com/morluto/rea): one MCP and an AI agent can take apart any site or app, record its sessions and rebuild it. Their showcase walks through Notion's clipboard bridge. We think that is simply where things are going, and you will not stop it with a bot wall. What you can do is make sure the clone carries your fingerprints. Hence NoREA.

## The problem

Public agencies and data businesses have to publish. Scrapers take it and resell it or train on it. Blocking (bot walls, obfuscation, fingerprinting) fights the reason the data is public, and it loses anyway. Map makers solved this decades ago with trap streets. Tables never got the equivalent. So we built it. We prove. We don't block.

## What it does

1. `inspect` looks at each field (kind, free value space, missing rate) and suggests marker fields to hide canaries in. It warns about fields with no free space, like serial numbers.
2. `protect` writes a new file with n fake records (default 32) that follow the field distributions, mixed into the real rows. Generation is a deterministic HMAC-based draw. No RNG. The input file is never modified.
3. Evidence: the Merkle root of the canary set, the hash of the encrypted canary blob, and the file hash get signed with ML-DSA-65 (FIPS 204). The owner keeps the evidence private.
4. `check` finds canaries in a suspect copy (CSV, JSON, HTML, plain text; renamed keys, nesting, full-width chars, NFD and row order don't matter) and counts matches. The verdict rule is marker k-of-n.
5. `disclose` / `norea-verify`: disclose only the matched canaries, each with its Merkle audit path. A reviewer runs `norea-verify disclosure` with no key, checks signature, Merkle, copy hash and reproduction, and gets a statement with an upper bound on the chance of an accidental match.

In the web app all of this runs in the browser (WASM). Data, canaries and keys never go to a server.

## What gets verified

Without a key, offline:
- the ML-DSA-65 signature on the evidence, `evidence_id = SHA-256(payload)`, and the canary blob hash
- that each disclosed canary's Merkle path leads to the signed canary_root
- that the submitted copy's SHA-256 equals the one in the disclosure (change one byte and it FAILs, exit 1)
- that the disclosed canaries actually reproduce in that copy

## What it does not prove

- When, if there is no anchor. RFC 3161 TSA anchors are added with `norea anchor <evidence.json> --tsa URL` (CLI only), and the verifier checks the token's imprint (= the signed evidence's anchor_subject) and genTime. An anchor that belongs to different evidence FAILs (exit 1). Without an anchor, evidence says nothing about when canaries were planted. `created_claim` is just what the owner's clock said, and the verifier prints exactly that. OpenTimestamps, a web anchor button and a relay don't exist yet.
- Where, when and how the copy was captured (`*_claim` fields). Owner claims.
- The TSA certificate chain and CMS signature. norea-verify reads only imprint and genTime. Check the chain yourself: `--export-anchors`, then `openssl ts -verify`.
- The probability bound is relative to our generator model, not the real world. The shape info it rests on is put in the disclosure by the owner.

## Timeline, honestly

This section exists because the rules say pre-session commits don't count, and we'd rather tell you than have you find out with `git log`.

- Nov 8: design documents (ADRs, protocol specs) written as preparation.
- Before the build session (commits at 00:16, 09:28, 09:57 KST on Nov 9): the workspace scaffold, the JSON/CSV table parser, the canary generator, and the evidence format with its frozen test vector.
- During the session (10:00 to 15:00): check/disclose and third-party verification, the CLI verifier, WASM bindings and key custody, the web UI, the RFC 3161 TSA anchor, and the demo.

The rules say pre-session commits are ineligible. Judge us on the session work. The git history shows the real timestamps.

## Run it

You need Rust (`rust-toolchain.toml` pins 1.99.1), `rustup target add wasm32-unknown-unknown`, `wasm-bindgen-cli` at the Cargo.lock version, and Node 22+.

```
./scripts/test.sh                          # everything: core, WASM e2e, platform contract, CLI, web UI static checks, getrandom 0
./scripts/demo.sh                          # the judge demo. output and log in target/demo/ (demo.log)
./scripts/build-web.sh                     # builds web/public/pkg
python3 -m http.server 8080 -d web/public  # http://localhost:8080
./target/release/norea anchor out/x.evidence.json --tsa https://freetsa.org/tsr  # RFC 3161 anchor -> out/x.anchored.json (network, needs curl)
```

`demo.sh` uses synthetic San Francisco real-estate listings (20,000 rows, `demo/data/sf-listings-synthetic.csv`, made by `scripts/demo-mkdata.mjs`; fake data, no real addresses or prices). inspect picks three markers (listing_id, price_usd, address) and a 2-of-3 rule. It protects with throwaway test keys from `/dev/urandom`, adds a freetsa.org anchor if the network is up (skips it if not), checks three crawler copies plus one unrelated file, builds a disclosure from the HTML copy, verifies it with `norea-verify`, and finally shows a one-byte-tampered copy failing. Synthetic San Francisco real-estate listings (20,000 rows), run on 2026-11-09 (Apple M4, about 3 s total):

| Copy | Match path | matched |
|---|---|---|
| HTML `<table>` (renamed columns, `&amp;`, line breaks and whitespace) | text | 32/32 |
| `{"status":"ok","data":[...]}` (renamed keys) | json | 32/32 |
| shuffled CSV (CRLF) | csv | 32/32 |
| Outer Sunset rows of the original input (no canaries) | csv | 0/32 |

`norea-verify disclosure` exits 0 (PASS), with a model chance-match bound of 2^-43.26. The one-byte-tampered copy exits 1 (FAIL, copy hash mismatch). Real data instead: `NOREA_DEMO_INPUT=demo/data/world-cities.csv` (GeoNames, CC BY 4.0, 34,195 rows) or `NOREA_DEMO_INPUT=demo/data/legal-dong-code.csv` (Korean MOLIT, 20,561 rows). Both also give 32/32, 32/32, 32/32, 0/32 (see `demo/data/NOTICE.md`).

`--key-file` and `--i-know-this-is-for-testing` on the CLI are for tests only. The web app wraps the key with WebAuthn PRF or a passphrase (Argon2id) and stores it in IndexedDB. On the web the key sits in browser memory while signing, and the UI says so.

## Repository layout

```
core/        noreacore: pure Rust (table, norm, shape, canary, merkle, blob, sign, evidence, check, disclose). No RNG, network, file I/O or clock
web/         norea-web: wasm-bindgen bindings. web/public/ is the static app (platform.js contract, custody.js key custody, app.js UI)
cli/         norea-verify (third-party verification, no secrets), norea (dev and test)
tests/       smoke.node.cjs (WASM e2e), platform.node.mjs (platform contract + custody), ui.node.mjs, vectors/ (frozen vectors)
scripts/     test.sh, build-web.sh, demo.sh, demo-crawler.mjs, demo-mkdata.mjs
demo/data/   bundled public demo inputs and their NOTICE
CONTEXT.md   current behavior. The source of truth for details
CLAUDE.md    working rules
```

## Frozen formats and vectors

Frozen: `norea.evidence.v1` (signing payload bytes, `SIG_CTX = "norea/evidence/v1"`, Merkle structure, blob AEAD), `record.shape.v1`, `norea.disclosure.v1`, `norea.disclosure-report.v1`, `norea.custody-backup.v1`, platform-contract v1. `core/tests/vectors.rs` checks the frozen vector `tests/vectors/norea-evidence-v1.json`, and `tests/smoke.node.cjs` checks that WASM `protect` on the same input produces byte-identical evidence. Change a format and every evidence already issued becomes unverifiable. So if a vector test breaks, we stop. We don't "fix" it.

## Measurements

Apple M4, rustc 1.99.1 release.

- Indistinguishability: on a real public CSV (MOLIT legal-dong codes, 20,561 rows), n = 1000, logistic regression, 5-fold held-out AUC 0.516 / 0.506 / 0.491 (three keys). 0.5 is a coin flip. Synthetic dataset A: 0.467 to 0.517.
- protect, 50k rows, 64 canaries, signing included: 437 to 447 ms (about 0.44 s). Measured in WASM under node 22 (`tests/smoke.node.cjs`), not in a real browser tab.
- check, 50k rows (n = 32, native release): JSON 5.7 MB about 94 ms, CSV 2.4 MB about 74 ms, HTML 10.5 MB about 143 ms.
- False matches: 0/128 (4 x 32) on four independent datasets made by dataset A's generator (seeds 2 to 5, none of our canaries). There are partials (14, 13, 15, 18), mostly chance hits in short id spaces.
- Tests: `./scripts/test.sh` ALL CHECKS PASSED (2026-11-09). 366 total: Rust 103 (core lib 68, check_disclose 15, vectors 1, shape_vectors 1, distinguishability 1, CLI unit 1 + e2e 16), WASM e2e 74, platform contract 84, UI 105.
- wasm is 782 KB after `wasm-opt -O3`. Target was 600 KB. We missed.

## Limits

- Full rewrite clones: if someone regenerates every value, there are no canaries to find. We only make picking canaries out expensive.
- Cross-field correlation (e.g. legal-dong code vs. province name) isn't learned. Neither are semantic rules like dates (`2003-02-31` can happen). An analyst who knows the correlations may spot canaries.
- Dense keys: a unique field with no free space, like serial `1..N`, can't hold canaries. inspect warns and suggests publishing without that field.
- EAV: a transform that splits one row's values across different arrays defeats the structural match path.
- Time anchors: RFC 3161 TSA via CLI only. No OTS, no web anchor button, no relay. TSA chain verification is a manual openssl step.
- WebAuthn PRF and Safari/Firefox are not yet tested in real browsers (only the passphrase path in headless Chrome).

## Design docs

English overview: `docs/DESIGN.md`. The original Korean design package (14 ADRs, 5 frozen protocols, architecture, threat model, API signatures) is in `docs/design/`, written on 2026-11-08. Reading order: `docs/design/README.md`. Current behavior: `CONTEXT.md`.

## License

MIT OR Apache-2.0 (see each crate's `Cargo.toml`).
