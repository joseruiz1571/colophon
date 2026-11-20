# Vendored from the Proof-of-Control Standard

Upstream: [LFDT-ProofOfControl/ov-poc-standard](https://github.com/LFDT-ProofOfControl/ov-poc-standard), commit `54a7bc67140b39c9107216cd390dd47c1d42946d` (2026-10-29), Working Draft v0.1.

© Advanced AI Society and the Proof-of-Control contributors. Licensed under the Apache License, Version 2.0: <https://www.apache.org/licenses/LICENSE-2.0>. These files are redistributed under that license; the rest of this repository is MIT.

| File here | Upstream path | Changed? | SHA-256 |
|---|---|---|---|
| `poc-checklist.csv` | `checklist/poc-checklist.csv` | no, byte-identical | `ad0aece140eea1fcfebbe2879197f07f3eb86038ba37ec832f86dea47a9cd66d` |
| `vectors/canonical/tricky-strings.json` | `schema/vectors/canonical/tricky-strings.json` | no, byte-identical | `ed9326078ce736a62583b9f2cf741443aa8305f70e55669e246df93631ecac1c` |
| `vectors/canonical/nonbmp-key-ordering.json` | `schema/vectors/canonical/nonbmp-key-ordering.json` | no, byte-identical | `6112d36bfdfe8125fa24d8606cfaf686d584e28815259167dc33a008a26441b6` |
| `vectors/manifest.json` | `schema/vectors/manifest.json` | **yes, an excerpt**: only `profile` and the two `canonical` entries are kept, and an `excerpt_of` field names the source. The signed evidence-token vectors and their key material are not vendored. | n/a |

What they are for:

- `poc-checklist.csv` is the list of the standard's 127 requirement ids. `tests/crosswalk.ts` reads it to confirm that every requirement `docs/proof-of-control.md` cites exists at this commit (S59).
- The canonical vectors carry the digests the standard expects from an RFC 8785 canonicalizer. `tests/poc-canonical.test.ts` runs Colophon's `canonicalSha256` over them (S60).

Refresh by replacing the files from a newer upstream commit, updating the commit and hashes above, and re-running `bun test tests/poc-canonical.test.ts` and `bun tests/crosswalk.ts`. A requirement that was renumbered or removed upstream shows up as `unresolved` in the crosswalk test.
