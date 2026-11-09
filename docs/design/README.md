# Design documents

Everything under `docs/design/` is the original design package, in Korean, written on 2026-11-08. The code (`core/`, `cli/`, `web/`) was built from it on 2026-11-09. Don't read Korean? `../DESIGN.md` is the English overview. Same facts, fewer words.

- `ARCHITECTURE.md`: layers, data pipeline, trust boundary, platform matrix, performance budget, limits
- `THREAT-MODEL.md`: assets, attackers, mitigations, what got turned into tests
- `CORE-API.md`: noreacore / norea-web / CLI signatures
- `SOURCES.md`: sources, marked with whether they were re-checked
- `protocol/`: the five frozen formats. `evidence-v1` (norea.evidence.v1), `canary-record-shape-v1` (generator and match rules), `disclosure-v1` (dispute package and third-party verification), `custody-web-v1` (web key custody and backup), `platform-contract` (the 17-function UI/platform contract)
- `adr/`: 14 decision records. Past tense, never edited

Frozen vectors are in `../../tests/vectors/`. WP numbers in the docs are implementation work packages (WP-00 to WP-11).
