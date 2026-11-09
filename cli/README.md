# norea-verify: for whoever has to check our claims

`norea-verify` checks a NoREA disclosure package offline, with no secrets (ADR-0011). You don't need our master key or signing key. It never touches the network. All the rules live in `noreacore`; this tool just reads files and prints what core says.

The operator hands you two files:
- `disclosure.json` (`norea.disclosure.v1`): the full signed evidence, the SHA-256 of the suspect copy, and the disclosed canary rows with their Merkle paths.
- The suspect file: the other party's copy, exactly as the operator says they captured it (JSON, CSV, HTML or plain text).

## Build

```
cargo build --release --locked -p norea-cli
# target/release/norea-verify, target/release/norea
```

## Commands

```
norea-verify disclosure <disclosure.json> <suspect-file> [--json] [--export-anchors DIR]
norea-verify evidence <evidence.json> [--json]
```

### disclosure

```
norea-verify disclosure disclosure.json suspect.json
```

You get `PASS` / `FAIL` / `N/A` per section:

1. Evidence: ML-DSA-65 signature (field rules included), `evidence_id = SHA-256(payload)`, canary blob hash.
2. Time anchors: for rfc3161 we check the token imprint (= anchor_subject) and read genTime, shown as `[PASS|FAIL]`. A missing or unparseable token, or another kind (ots), is `N/A`. A checked anchor with the wrong imprint is someone else's anchor, so it FAILs.
3. Suspect copy: does the file's SHA-256 equal `suspect.sha256` in the disclosure?
4. Disclosed canaries: does each row's Merkle path reach the **signed** `canary_root` (using the signed `canary_count`), and does the row show up again in the suspect copy (reproduced)? Per item: `index`, `found`.
5. Verdict: `verdict.integrity_ok`, `verdict.all_reproduced`.
6. Statement: the verifier's own text, verbatim. It has the public key fingerprint (first 16 hex of SHA-256(vk)), the time line, "Reproduced: M of N disclosed canaries were reproduced in the suspect copy.", the probability upper bound, and a line saying the `*_claim` fields are unverified. If you quote us in a report, quote this.

`--json` prints the `norea.disclosure-report.v1` JSON untouched, one line, one trailing newline. Nothing else goes to stdout.

### evidence

```
norea-verify evidence evidence.json
```

Checks one `norea.evidence.v1` on its own: signature, evidence_id, blob hash, anchors. `--json` prints core's `EvidenceVerification` JSON (`signature_ok, evidence_id_ok, blob_hash_ok, anchors, has_anchors`) as is.

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `disclosure` | `verdict.integrity_ok && verdict.all_reproduced` | Anything else: a failed signature, evidence_id, blob hash, suspect hash, Merkle path or reproduction; zero disclosed; or a checked anchor with a wrong imprint | Input error: missing file, not UTF-8, not JSON, bad schema or field format, index order, an `--export-anchors` target that already exists |
| `evidence` | `signature_ok && evidence_id_ok && blob_hash_ok && anchors_consistent` | Anything else (including a checked anchor with a wrong imprint) | Missing file, not JSON, not an evidence object |

In both commands, one checked anchor (no `error`) with a wrong imprint means exit 1 (`anchors_consistent`, disclosure-v1 §4). `N/A` anchors don't count. Errors are one line on stderr (`norea-verify: error: ...`). No stack traces.

## Check the TSA tokens yourself (`--export-anchors DIR`)

```
norea-verify disclosure disclosure.json suspect.json --export-anchors anchors/
```

Writes new files into `DIR`. It refuses to overwrite anything (exit 2).
- `anchor-<k>.tsr`: TimeStampToken (DER) of rfc3161 anchor k.
- `anchor-<k>.ots`: proof bytes of ots anchor k. We haven't pinned the OpenTimestamps verify command yet (waiting on a real proof). The file is the raw proof.
- `subject.bin`: anchor_subject, 32 B = SHA-256(signing payload || 0x0A || signature).
- `README.txt`: the command below with real values filled in.

```
openssl ts -verify -digest <anchor_subject_hex> -in anchor-0.tsr -token_in -CAfile <TSA CA bundle>
```

Get the CA bundle from the TSA yourself. We deliberately don't automate this step (disclosure-v1 §5). Trusting our tool to fetch the thing that checks our tool would be a bit circular.

## What this tool does not verify

- **TSA certificate chain.** `chain_verified` is always `false`. Export the tokens and run `openssl ts -verify`.
- **CMS signature and cert chain of TSA tokens.** For rfc3161 we only read imprint and genTime. Check the chain with openssl after `--export-anchors`. OpenTimestamps anchors aren't verified yet (`N/A`).
- **`*_claim` fields.** `created_claim` (the operator's device clock), `suspect.source_claim`, `captured_claim`, `capture_method_claim` are operator claims. When, where and how the copy was captured needs outside evidence: notarization, platform timestamps, web archives.
- **Shape info.** The `shape` behind the probability line comes from the operator's disclosure. We don't verify it.
- **Real-world probability.** The probability line is an upper bound under the canary generator model. It is not the odds of the same values showing up by chance in real data.
- **Undisclosed canaries.** They stay inside the encrypted blob. We only check its hash.
- **Whether the copy legally derives from the operator's data.** That's for a human. We report technical facts: signature, hashes, Merkle, reproduction.

## `norea` (dev and testing only, not the product)

```
norea inspect <input> [--format json|csv]
norea protect <input> --dataset-id ID --n N [--markers a,b] [--exclusions file] [--created-claim YYYY-MM-DDTHH:MM:SSZ] --key-file K.bin --seed-file S.bin --out-dir DIR --i-know-this-is-for-testing
norea check <suspect> <evidence.json> --key-file K.bin --i-know-this-is-for-testing
norea disclose <evidence.json> <suspect> --key-file K.bin [--indices 1,2,3] [--source-claim S] [--captured-claim T] [--capture-method-claim M] [--created-claim YYYY-MM-DDTHH:MM:SSZ] [--force] --out disclosure.json --i-know-this-is-for-testing
norea anchor <evidence.json> --tsa URL [--ots]
```

- Key files (`K.bin`, `S.bin`) are raw 32 B and **for testing only**. Without `--i-know-this-is-for-testing` we refuse and exit 2. Don't keep real keys in files. The product uses web/app custody.
- `protect` never touches the input. It creates `DIR/<stem>.marked.<json|csv>` and `DIR/<stem>.evidence.json`. If either exists, it writes nothing and exits 2. `--exclusions` is a UTF-8 file, one value per line, blank lines ignored.
- `created_claim` comes from `--created-claim`, or this machine's clock (UTC) if you leave it out. It's a claim, not proof of time. A malformed value is refused by core (exit 2).
- `--source-claim`, `--captured-claim`, `--capture-method-claim` go verbatim into `suspect.*_claim`. Operator claims. Nobody verifies them, and core doesn't even check the format.
- `check` prints `norea.check-report.v1` JSON to stdout (exit 0). `disclose` writes a new file at `--out` (exit 2 if it exists). `disclose` won't disclose an unmatched canary. `--force` makes it, and that item then shows up as NOT REPRODUCED, so `norea-verify` exits 1. You asked for it.
- `anchor --tsa URL`: builds a TimeStampReq from anchor_subject, POSTs it with system `curl`, checks the imprint, writes a new `<stem>.anchored.json` (input unchanged). No curl, network trouble or a bad response: exit 2. `--ots` isn't implemented yet (exit 3, no network).
- Keys, K_d and seeds never appear in any output and are zeroed in memory after use.
