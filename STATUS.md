# STATUS

Probe run: `bun tests/probes.ts` at HEAD `d8a84ec`, 2026-09-10T15:57:12.720Z, from a fresh `git clone` into a temp directory with `bun install --frozen-lockfile`. Bun 1.4.0, OPA 1.19.1, Cosign v3.1.3, jq 1.8.2, gitleaks 8.30.1, macOS. Results file: `out/probes.json` (gitignored; regenerate with the command above).

A row is `done` only if its probe passed in that run. `partial` means the probe passed but the claim's full meaning was not exercised, with the reason stated. `not-started` means the probe failed or did not run.

**39 done · 1 partial · 0 not-started** of 40 claims (S1–S37, A1–A3).

Not claimed anywhere in this repository: a live AWS collector, an OWASP contribution, in-toto co-authorship, any certification, a green CI run (see S37).

| # | claim | status | probe run | note |
|---|---|---|---|---|
| S16 | `bun run demo` from a fresh clone exits 0 in under 90 s with no network, writes only under `out/`, and prints `SIGNATURE: <path>` for each packet. | done | `bun tests/probes.ts` S16 at d8a84ec, 10.0s |  |
| S1 | `packages/schema/declaration.schema.json` is JSON Schema 2020-12 and requires `id, name, owner, risk_tier, autonomy_level, tools, data_classes, san… | done | `bun tests/probes.ts` S1 at d8a84ec, 0.0s |  |
| S2 | `$CLI declare validate <file>` exits 0 for every shipped declaration and exits 1 naming the field for a declaration missing `owner`. | done | `bun tests/probes.ts` S2 at d8a84ec, 0.7s |  |
| S3 | `$CLI record build <decl> --out <dir>` writes `<id>.record.json` valid against `record.schema.json`; `canonical_sha256` is SHA-256 over the RFC 878… | done | `bun tests/probes.ts` S3 at d8a84ec, 0.7s |  |
| S4 | `$CLI record lint <record>` evaluates `packages/policy/record.rego` through OPA: denies a past `review_due`, denies `high`/`critical` without `kill… | done | `bun tests/probes.ts` S4 at d8a84ec, 1.3s |  |
| S5 | Records are Cosign-signed. `$CLI record sign --key` writes `<id>.record.sigstore.json`; `$CLI record verify --pubkey` exits 0; the gate refuses to … | done | `bun tests/probes.ts` S5 at d8a84ec, 0.6s |  |
| S6 | `packages/policy/gate.rego` produces `data.colophon.gate.decision = {effect, rule_ids, reasons}` and, for the shipped inputs, `in-scope`→allow, `un… | done | `bun tests/probes.ts` S6 at d8a84ec, 0.3s |  |
| S7 | Every deny in every demo trace carries ≥1 `rule_ids` entry and ≥1 `reasons` entry whose `field` names a Record field. | done | `bun tests/probes.ts` S7 at d8a84ec, 0.0s |  |
| S8 | `opa test packages/policy -v` passes ≥ 20 tests covering allow, deny, and escalate for every rule ID; `opa fmt --list packages/policy` prints nothing. | done | `bun tests/probes.ts` S8 at d8a84ec, 0.1s |  |
| S9 | Changing one line in `gate.rego` changes a demo decision with zero `.ts` changes. | done | `bun tests/probes.ts` S9 at d8a84ec, 5.8s |  |
| S10 | If OPA errors (here: the gate policy path points at a file that does not exist), the gate denies every call with `COL-GATE-OPA-ERROR` and logs the … | done | `bun tests/probes.ts` S10 at d8a84ec, 3.0s |  |
| S11 | No TypeScript file contains an allow/deny branch keyed on a tool name, path, scope, or data class. | done | `bun tests/probes.ts` S11 at d8a84ec, 0.0s |  |
| S12 | The gate is an MCP stdio server: `tools/list` returns exactly the record's tool names present upstream; the calls that reached the upstream are exa… | done | `bun tests/probes.ts` S12 at d8a84ec, 3.1s |  |
| S13 | Every trace line validates against `packages/schema/decision.schema.json` with fields `source, effect, rule_ids, reasons, tool, args_sha256, ts, pr… | done | `bun tests/probes.ts` S13 at d8a84ec, 0.2s |  |
| S14 | `this_sha256` is SHA-256 over the RFC 8785 form of the line without `this_sha256`; `prev_sha256` links lines; `$CLI trace verify` exits 1 naming th… | done | `bun tests/probes.ts` S14 at d8a84ec, 0.2s |  |
| S15 | The synthetic token literal from the evidence-reader scenario appears nowhere under `out/demo`; its SHA-256 does (secret-shaped argument values are… | done | `bun tests/probes.ts` S15 at d8a84ec, 0.1s |  |
| S17 | The evidence-reader trace contains four distinct deny rule IDs — `COL-GATE-UNKNOWN-TOOL`, `COL-GATE-SCOPE`, `COL-GATE-SANDBOX`, `COL-GATE-DATACLASS… | done | `bun tests/probes.ts` S17 at d8a84ec, 0.0s |  |
| S18 | `bun run demo` twice in a row succeeds. | done | `bun tests/probes.ts` S18 at d8a84ec, 20.1s |  |
| S19 | When signing fails, the demo exits 1, stderr names cosign, no `*.sigstore.json` is written for the failed packet, and no `SIGNATURE:` line is printed. | done | `bun tests/probes.ts` S19 at d8a84ec, 0.2s |  |
| S20 | Evidence ids are the SHA-256 of the canonical payload; the store rejects a duplicate id and an item whose `sha256` does not match its payload. | done | `bun tests/probes.ts` S20 at d8a84ec, 0.1s |  |
| S21 | `packages/catalog/controls.yaml` defines ≥ 8 controls, each with `id, title, intent, framework_refs, phase (assess\|verify), check`, covering decla… | done | `bun tests/probes.ts` S21 at d8a84ec, 0.1s |  |
| S22 | `report/assessment-results.json` validates against the vendored OSCAL 1.2.3 Assessment Results schema. | done | `bun tests/probes.ts` S22 at d8a84ec, 0.4s |  |
| S23 | Every observation's `relevant-evidence.href` resolves to a back-matter resource whose `rlinks[0].href` is a bundle-relative path whose SHA-256 matc… | done | `bun tests/probes.ts` S23 at d8a84ec, 0.5s |  |
| S24 | Citation guard: a report that would cite an evidence id not in the store fails before writing with `CitationError`, and no file is written. | done | `bun tests/probes.ts` S24 at d8a84ec, 0.1s |  |
| S25 | `narrative.md` contains a proves / does-not-prove table, the sentence `Custody is provable. Judgment is not.`, and never the word `vacuous`. | done | `bun tests/probes.ts` S25 at d8a84ec, 0.0s |  |
| S26 | For a shipped breach trace (an out-of-scope call executed), the report marks the gate control `not-satisfied`. | done | `bun tests/probes.ts` S26 at d8a84ec, 0.7s |  |
| S27 | `bundle create` writes `manifest.json` last with per-file `sha256`, `bytes`, and a `root_sha256`; it refuses a non-empty output directory. | done | `bun tests/probes.ts` S27 at d8a84ec, 0.2s |  |
| S28 | `bundle verify` exits 1 naming the file after any single byte change, any added file, or any removed file. | done | `bun tests/probes.ts` S28 at d8a84ec, 1.0s |  |
| S29 | `bundle sign --key` writes `manifest.sigstore.json` (Cosign 3 bundle format); `bundle verify --pubkey` exits 0 on it and exits 1 when the signature… | done | `bun tests/probes.ts` S29 at d8a84ec, 0.5s |  |
| S30 | `bundle verify --out <dir>` writes a second OSCAL AR (`verification-results.json`) outside the bundle with findings for the verify-phase controls (… | done | `bun tests/probes.ts` S30 at d8a84ec, 0.9s |  |
| S31 | The claude-hook adapter normalizes a fixture JSONL of PreToolUse events into chained Decisions and the demo runs the same catalog to a signed, veri… | done | `bun tests/probes.ts` S31 at d8a84ec, 0.9s | Foreign PEP: three of eight assess-phase controls are not-satisfied because no Record is bound; this is the honest shape of "their gate, your packet". |
| S32 | The aws-config adapter is an interface plus a fixture reader shaped like CloudTrail `LookupEvents`, IAM `GetRolePolicy`, and S3 `GetBucketEncryptio… | done | `bun tests/probes.ts` S32 at d8a84ec, 0.3s | Fixture-only by design: interface + fixture reader, no SDK, no live client. A live provider is out of scope and is not claimed. |
| S33 | README states the one-sentence product, the design rule, a proves / does-not-prove table, exactly the two commands, and points at STATUS.md. | done | `bun tests/probes.ts` S33 at d8a84ec, 0.0s |  |
| S34 | STATUS.md has one row per claim S1–S37 and A1–A3; every `done` row names the probe run and the session date. | done | `bun tests/probes.ts` S34 at d8a84ec, 0.0s |  |
| S35 | DECISIONS.md records only decisions made in this repo, each with a rationale; it contains no operator brief. | done | `bun tests/probes.ts` S35 at d8a84ec, 0.0s |  |
| S36 | `bun test` passes and `bun run typecheck` exits 0. | done | `bun tests/probes.ts` S36 at d8a84ec, 2.8s |  |
| S37 | `.github/workflows/ci.yml` pins Bun and Cosign 3.x, runs `bun install --frozen-lockfile`, typecheck, `bun test`, `opa test`, `bun run demo`, `bun t… | partial | `bun tests/probes.ts` S37 at d8a84ec, 0.0s | The workflow is written and pinned and the static probe passes, but it has never executed: the repository has not been pushed to GitHub, so the keyless Sigstore signing path and the green-run half of the claim are unexercised. Needs: push to a GitHub repo with `id-token: write` and read the run. |
| A1 | No signing fallback: no code path continues after a failed sign; `signed` is never written by a code path that did not verify. | done | `bun tests/probes.ts` A1 at d8a84ec, 0.0s |  |
| A2 | No LLM provider SDK and no AWS SDK in `package.json`. | done | `bun tests/probes.ts` A2 at d8a84ec, 0.0s |  |
| A3 | `gitleaks` finds no secret in the tree (demo keys live under `out/`, which is gitignored and allowlisted). | done | `bun tests/probes.ts` A3 at d8a84ec, 0.2s |  |

## What "done" means here

- Fresh clone: `bun run demo` exits 0 and writes a Cosign 3 bundle (`manifest.sigstore.json`) per packet — S16, S29.
- Tamper one trace byte → `trace verify` names the line — S14; tamper, add, or remove a bundle file → `bundle verify` names the file — S28.
- Missing signature → `bundle verify` exits 1 — S29; signing failure → demo exits 1 with no `SIGNATURE:` line — S19.
- Four distinct deny rule ids in the evidence-reader trace, a fifth on the notifier — S17.
- Verdicts only from Rego: a one-line policy edit flips a decision with zero `.ts` changes — S9; OPA failure denies — S10.
- STATUS matches probes: this file is generated from the probe run it cites (`tests/write-status.ts`).
- DECISIONS has no fictional operator — S35.
