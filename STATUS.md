# STATUS

Probe run: `bun tests/probes.ts` at HEAD `46a9e30`, 2026-09-16T03:32:53.869Z, from a fresh `git clone` into a temp directory with `bun install --frozen-lockfile`. Bun 1.4.0, OPA 1.19.1, Cosign v3.1.3, jq 1.8.2, gitleaks 8.30.1, macOS. Results file: `out/probes.json` (gitignored; regenerate with the command above). This file is generated from that run and committed afterwards, so the HEAD it cites is the commit immediately before the one that adds it; rerunning the probes at the STATUS commit itself is how a reader confirms nothing moved.

A row is `done` only if its probe passed in that run. `partial` means the probe passed but the claim's full meaning was not exercised, with the reason stated. `not-started` means the probe failed or did not run.

**45 done · 0 partial · 1 not-started** of 46 claims (S1–S43, A1–A3).

Not claimed anywhere in this repository: a live CloudWatch/EventBridge collector, an OWASP contribution, in-toto co-authorship, any certification.

| # | claim | status | probe run | note |
|---|---|---|---|---|
| S16 | `bun run demo` from a fresh clone exits 0 in under 90 s with no network, writes only under `out/`, and prints `SIGNATURE: <path>` for each packet. | done | `bun tests/probes.ts` S16 at 46a9e30, 13.1s |  |
| S1 | `packages/schema/declaration.schema.json` is JSON Schema 2020-12 and requires `id, name, owner, risk_tier, autonomy_level, tools, data_classes, san… | done | `bun tests/probes.ts` S1 at 46a9e30, 0.0s |  |
| S2 | `$CLI declare validate <file>` exits 0 for every shipped declaration and exits 1 naming the field for a declaration missing `owner`. | done | `bun tests/probes.ts` S2 at 46a9e30, 1.2s |  |
| S3 | `$CLI record build <decl> --out <dir>` writes `<id>.record.json` valid against `record.schema.json`; `canonical_sha256` is SHA-256 over the RFC 878… | done | `bun tests/probes.ts` S3 at 46a9e30, 1.0s |  |
| S4 | `$CLI record lint <record>` evaluates `packages/policy/record.rego` through OPA: denies a past `review_due`, denies `high`/`critical` without `kill… | done | `bun tests/probes.ts` S4 at 46a9e30, 1.8s |  |
| S5 | Records are Cosign-signed. `$CLI record sign --key` writes `<id>.record.sigstore.json`; `$CLI record verify --pubkey` exits 0; the gate refuses to … | done | `bun tests/probes.ts` S5 at 46a9e30, 0.5s |  |
| S6 | `packages/policy/gate.rego` produces `data.colophon.gate.decision = {effect, rule_ids, reasons}` and, for the shipped inputs, `in-scope`→allow, `un… | done | `bun tests/probes.ts` S6 at 46a9e30, 0.2s |  |
| S7 | Every deny in every demo trace carries ≥1 `rule_ids` entry and ≥1 `reasons` entry whose `field` names a Record field. | done | `bun tests/probes.ts` S7 at 46a9e30, 0.0s |  |
| S8 | `opa test packages/policy -v` passes ≥ 20 tests covering allow, deny, and escalate for every rule ID; `opa fmt --list packages/policy` prints nothing. | done | `bun tests/probes.ts` S8 at 46a9e30, 0.1s |  |
| S9 | Changing one line in `gate.rego` changes a demo decision with zero `.ts` changes. | done | `bun tests/probes.ts` S9 at 46a9e30, 5.8s |  |
| S10 | If OPA errors (here: the gate policy path points at a file that does not exist), the gate denies every call with `COL-GATE-OPA-ERROR` and logs the … | done | `bun tests/probes.ts` S10 at 46a9e30, 2.9s |  |
| S11 | No TypeScript file names a gate effect except the fail-closed deny in `packages/gate/eval.ts` (`COL-GATE-OPA-ERROR`) and the adapters' translation … | done | `bun tests/probes.ts` S11 at 46a9e30, 0.0s |  |
| S12 | The gate is an MCP stdio server: `tools/list` returns exactly the record's tool names present upstream; the calls that reached the upstream are exa… | done | `bun tests/probes.ts` S12 at 46a9e30, 3.1s |  |
| S13 | Every trace line validates against `packages/schema/decision.schema.json` with fields `source, effect, rule_ids, reasons, tool, args_sha256, ts, pr… | done | `bun tests/probes.ts` S13 at 46a9e30, 0.2s |  |
| S14 | `this_sha256` is SHA-256 over the RFC 8785 form of the line without `this_sha256`; `prev_sha256` links lines; `$CLI trace verify` exits 1 naming th… | done | `bun tests/probes.ts` S14 at 46a9e30, 0.2s |  |
| S15 | The synthetic credential from the evidence-reader scenario (passed under a `token` key) appears nowhere under `out/demo`; its SHA-256 does (secret-… | done | `bun tests/probes.ts` S15 at 46a9e30, 0.1s |  |
| S41 | Redaction is substring-based with the same credential pattern COL-10 scans for: a token embedded inside a `Bash` command in a claude-hook event is … | done | `bun tests/probes.ts` S41 at 46a9e30, 0.3s |  |
| S42 | A packet whose COL-10 (no credential values) is not-satisfied is refused before signing: `buildPacket` throws naming `COL-10`, writes no bundle, an… | done | `bun tests/probes.ts` S42 at 46a9e30, 0.5s |  |
| S43 | No file in any demo bundle carries the build machine's absolute path: narrative, session.json, evidence items, and the OSCAL AR name fixture and bu… | done | `bun tests/probes.ts` S43 at 46a9e30, 0.1s |  |
| S17 | The evidence-reader trace contains four distinct deny rule IDs — `COL-GATE-UNKNOWN-TOOL`, `COL-GATE-SCOPE`, `COL-GATE-SANDBOX`, `COL-GATE-DATACLASS… | done | `bun tests/probes.ts` S17 at 46a9e30, 0.0s |  |
| S18 | `bun run demo` twice in a row succeeds. | done | `bun tests/probes.ts` S18 at 46a9e30, 25.7s |  |
| S19 | When `cosign sign-blob` fails over a bundle manifest (records signed, session run, bundle created, then the manifest signature fails), the demo exi… | done | `bun tests/probes.ts` S19 at 46a9e30, 6.5s |  |
| S20 | Evidence ids are the SHA-256 of the canonical payload; the store rejects a duplicate id and an item whose `sha256` does not match its payload. | done | `bun tests/probes.ts` S20 at 46a9e30, 0.1s |  |
| S21 | `packages/catalog/controls.yaml` defines ≥ 8 controls, each with `id, title, intent, framework_refs, phase (assess\|verify), check`, covering decla… | done | `bun tests/probes.ts` S21 at 46a9e30, 0.1s |  |
| S22 | `report/assessment-results.json` validates against the vendored OSCAL 1.2.3 Assessment Results schema. | done | `bun tests/probes.ts` S22 at 46a9e30, 0.4s |  |
| S23 | Every observation's `relevant-evidence.href` resolves to a back-matter resource whose `rlinks[0].href` is a bundle-relative path whose SHA-256 matc… | done | `bun tests/probes.ts` S23 at 46a9e30, 0.5s |  |
| S24 | Citation guard: a report that would cite an evidence id not in the store fails before writing with `CitationError`, and no file is written. | done | `bun tests/probes.ts` S24 at 46a9e30, 0.1s |  |
| S25 | `narrative.md` contains a proves / does-not-prove table, the sentence `Custody is provable. Judgment is not.`, and never the word `vacuous`. | done | `bun tests/probes.ts` S25 at 46a9e30, 0.0s |  |
| S26 | For a shipped breach trace (an out-of-scope call executed), the report marks the gate control `not-satisfied`. | done | `bun tests/probes.ts` S26 at 46a9e30, 0.6s |  |
| S27 | `bundle create` writes `manifest.json` last with per-file `sha256`, `bytes`, and a `root_sha256`; it refuses a non-empty output directory. | done | `bun tests/probes.ts` S27 at 46a9e30, 0.2s |  |
| S28 | `bundle verify` exits 1 naming the file after any single byte change, any added file, or any removed file. | done | `bun tests/probes.ts` S28 at 46a9e30, 1.8s |  |
| S29 | `bundle sign --key` writes `manifest.sigstore.json` (Cosign 3 bundle format); `bundle verify --pubkey` exits 0 on it and exits 1 when the signature… | done | `bun tests/probes.ts` S29 at 46a9e30, 0.5s |  |
| S30 | `bundle verify --out <dir>` writes a second OSCAL AR (`verification-results.json`) outside the bundle with findings for the verify-phase controls (… | done | `bun tests/probes.ts` S30 at 46a9e30, 0.9s |  |
| S31 | The claude-hook adapter normalizes a fixture JSONL of PreToolUse events into chained Decisions and the demo runs the same catalog to a signed, veri… | done | `bun tests/probes.ts` S31 at 46a9e30, 0.9s | Foreign PEP: three of eight assess-phase controls are not-satisfied because no Record is bound; this is the honest shape of "their gate, your packet". |
| S32 | The aws-config adapter is an interface plus a fixture reader shaped like CloudTrail `LookupEvents`, IAM `GetRolePolicy`, and S3 `GetBucketEncryptio… | done | `bun tests/probes.ts` S32 at 46a9e30, 0.3s | Fixture-only by design: interface + fixture reader, no SDK, no live client. A live provider is out of scope and is not claimed. |
| S38 | The agentcore-dogwood adapter normalizes fixture AgentCore/Dogwood AuthorizeAction events (approve-before-act, out-of-scope, rate-limit, simple all… | done | `bun tests/probes.ts` S38 at 46a9e30, 1.2s | AuthorizeAction fixture replay. Colophon does not reimplement Dogwood. APPLICATION_LOGS capture ingest is S40. No CloudWatch/EventBridge SDK client. aws-config remains a separate CloudTrail/IAM adapter. |
| S39 | `colophon export finding` maps sealed Decisions to GRC Eng Club `finding.schema.json` v1 (resource `ai_agent_session`, Colophon COL-* evaluations, … | done | `bun tests/probes.ts` S39 at 46a9e30, 0.9s | Finding export is club interop on the Decision stream, not a CloudTrail collector. SCF control IDs are not emitted. Dual-emit of CloudTrail is deferred. |
| S40 | The agentcore-dogwood adapter ingests captured AgentCore Gateway APPLICATION_LOGS JSONL: joins `Started processing request` to `Policy evaluation c… | done | `bun tests/probes.ts` S40 at 46a9e30, 2.1s | Phase 4 is captured APPLICATION_LOGS JSONL ingest, not a live CloudWatch collector. Session id is sidecar/CLI metadata — AgentCore Gateway logs do not carry it. ENFORCE + AWS_IAM named principal. No AWS SDK. |
| S33 | README states the one-sentence product, the design rule, a proves / does-not-prove table, exactly the two commands, and points at STATUS.md. | done | `bun tests/probes.ts` S33 at 46a9e30, 0.0s |  |
| S34 | STATUS.md has one row per claim S1–S43 and A1–A3; every `done` row names the probe run and the session date. | not-started | `bun tests/probes.ts` S34 at 46a9e30, 0.0s | probe failed in the last run |
| S35 | DECISIONS.md records only decisions made in this repo, each with a rationale; it contains no operator brief. | done | `bun tests/probes.ts` S35 at 46a9e30, 0.0s |  |
| S36 | `bun test` passes and `bun run typecheck` exits 0. | done | `bun tests/probes.ts` S36 at 46a9e30, 3.2s |  |
| S37 | `.github/workflows/ci.yml` pins Bun and Cosign 3.x, runs `bun install --frozen-lockfile`, typecheck, `bun test`, `opa test`, `bun run demo`, `bun t… | done | `bun tests/probes.ts` S37 at 46a9e30, 0.0s | CI ran green on the first push: https://github.com/joseruiz1571/colophon/actions/runs/34505148818 (2026-09-10). The keyless demo signed four bundles against the public Sigstore instance and `bundle verify` passed with the pinned certificate identity and issuer; the fresh-clone probe suite passed in full inside CI (40 claims at the time; the count above is current). Actions are pinned to commit SHAs. |
| A1 | No signing fallback: no code path continues after a failed sign; `signed` is never written by a code path that did not verify. | done | `bun tests/probes.ts` A1 at 46a9e30, 0.0s |  |
| A2 | No LLM provider SDK and no AWS SDK in `package.json`. | done | `bun tests/probes.ts` A2 at 46a9e30, 0.0s |  |
| A3 | `gitleaks` finds no secret in the tree (demo keys live under `out/`, which is gitignored and allowlisted). | done | `bun tests/probes.ts` A3 at 46a9e30, 0.2s |  |

## What "done" means here

- Fresh clone: `bun run demo` exits 0 and writes a Cosign 3 bundle (`manifest.sigstore.json`) per packet — S16, S29.
- Tamper one trace byte → `trace verify` names the line — S14; tamper, add, or remove a bundle file → `bundle verify` names the file — S28.
- Missing signature → `bundle verify` exits 1 — S29; signing failure → demo exits 1 with no `SIGNATURE:` line — S19.
- Four distinct deny rule ids in the evidence-reader trace, a fifth on the notifier — S17.
- Verdicts only from Rego: a one-line policy edit flips a decision with zero `.ts` changes — S9; OPA failure denies — S10.
- STATUS matches probes: this file is generated from the probe run it cites (`tests/write-status.ts`).
- DECISIONS has no fictional operator — S35.
