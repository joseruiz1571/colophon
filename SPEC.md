# Colophon — Specification (lineage: charlie)

> A colophon is the note at the back of a book saying who made it, where, and how. Colophon is that note for an AI agent session: a signed packet recording what the agent was allowed to do, what it tried, what was refused, and the evidence behind each fact.

**One-sentence product.** Colophon emits a signed session packet: operator **Declaration** → signed **Record** → **Decisions** from a policy enforcement point (the reference MCP gate or a foreign adapter) → hash-chained **Trace** → content-addressed **Evidence** → control findings as **OSCAL Assessment Results** → Cosign-signed **bundle** a stranger can verify with only the directory and a public key.

The gate is the reference microphone. The packet is the product.

**Design rule.** Custody is provable. Judgment is not.

This document defines done. Every numbered claim below has a command-line probe. A claim is `done` in `STATUS.md` only after its probe ran from a fresh clone in the session that wrote the row.

---

## 1. Language

| Term | Meaning | Avoid |
|---|---|---|
| Declaration | Operator-authored YAML or JSON. Unsigned intent. | "config" |
| Record | The Declaration canonicalized (RFC 8785), hashed, and Cosign-signed. What the gate binds to at runtime. | "Agent Card" (an A2A Agent Card may appear only as `identity.a2a_card_uri`) |
| PEP | Policy enforcement point. The reference PEP is the MCP gate; foreign PEPs enter through adapters. | |
| Decision | One PEP-agnostic verdict: `allow`, `deny`, or `escalate`, with rule IDs and reasons. | |
| Trace | Append-only, hash-chained JSONL of Decisions for one session. | "log" |
| Evidence | One content-addressed payload; id is the SHA-256 of its canonical form. | |
| Bundle | A directory: records, traces, evidence, report, manifest, signature. | |
| Packet | The bundle plus its signature — the deliverable. | |

## 2. Constraints

- Bun ≥ 1.2, TypeScript `strict`. OPA ≥ 1.0 with `import rego.v1`. Cosign 3.x. `bun`/`bunx` only.
- No live AWS, no network LLM, no paid API in tests, demo, or CI. Fixture replay only. Network is permitted only for `bun install` and, in CI only, Sigstore keyless signing.
- Every gate verdict comes from Rego evaluated by OPA. TypeScript routes inputs and outputs and fails closed; it never decides.
- Fail closed end to end. A signing failure exits non-zero and nothing prints `SIGNATURE:`.
- No credential value, synthetic or real, appears in any trace, evidence item, report, or bundle. Arguments are stored as their SHA-256 plus a redacted view.
- All names, repos, tokens, and people in fixtures are synthetic; domains use `.example`.

## 3. Repo layout

```
colophon/
  SPEC.md STATUS.md DECISIONS.md README.md
  packages/
    schema/      JSON Schema 2020-12: declaration, record, decision; record builder
    policy/      Rego: record.rego (lint), gate.rego (verdicts), tests
    gate/        reference MCP stdio PEP + demo upstream + scenario runner
    trace/       hash chain, redaction, chain verify
    normalize/   PEP-agnostic Decision type
    evidence/    content-addressed store + citation guard
    catalog/     YAML controls + deterministic checks
    report/      OSCAL AR 1.2.3 + narrative + back-matter rlinks
    bundle/      manifest, sign, verify
    adapters/    colophon-gate, claude-hook (fixture), aws-config (CloudTrail/IAM fixture), agentcore-dogwood (AgentCore+Dogwood fixture; no live AWS)
    export/      GRC Eng Club Finding v1 speaker (Decision stream → finding.schema.json; not a collector)
    cli/         `colophon` entry point
    fixtures/    declarations, scenarios, gate inputs, hook events, aws, upstream tree
  tests/         unit tests + probes.ts (runs every probe below from a fresh clone)
  .github/workflows/ci.yml
```

## 4. Claims and probes

`$CLI` is `bun packages/cli/main.ts`. Probes run from the repo root of a fresh clone after `bun install --frozen-lockfile`. `$OUT` is `out/demo` after `bun run demo`. Exit codes are literal.

### F1 · Declaration and Record

| # | Claim | Probe | Pass |
|---|---|---|---|
| S1 | `packages/schema/declaration.schema.json` is JSON Schema 2020-12 and requires `id, name, owner, risk_tier, autonomy_level, tools, data_classes, sandbox, max_scopes, kill_switch, review_due, control_mappings`. | `jq -r '."$schema", (.required\|sort\|join(","))' packages/schema/declaration.schema.json` | first line contains `2020-12`; second lists all twelve fields |
| S2 | `$CLI declare validate <file>` exits 0 for every shipped declaration and exits 1 naming the field for a declaration missing `owner`. | `for f in packages/fixtures/declarations/*.yaml; do $CLI declare validate "$f" \|\| exit 1; done; $CLI declare validate packages/fixtures/declarations/bad/missing-owner.yaml` | loop exits 0; final command exits 1 and output contains `owner` |
| S3 | `$CLI record build <decl> --out <dir>` writes `<id>.record.json` valid against `record.schema.json`; `canonical_sha256` is SHA-256 over the RFC 8785 form excluding that field; `$CLI record verify` exits 1 on mismatch. | `$CLI record build packages/fixtures/declarations/evidence-reader.yaml --out out/probe/ && R=$(ls out/probe/*.record.json) && $CLI record verify "$R" --hash-only && jq '.canonical_sha256="0000"' "$R" > out/probe/tampered.json; $CLI record verify out/probe/tampered.json --hash-only; $CLI record verify "$R"` | build+verify exit 0; tampered verify exits 1; verify without `--pubkey` or `--hash-only` exits 1 |
| S4 | `$CLI record lint <record>` evaluates `packages/policy/record.rego` through OPA: denies a past `review_due`, denies `high`/`critical` without `kill_switch.available`, denies an `auth.*` tool with empty `max_scopes`; allows both shipped records. | `$CLI record lint packages/fixtures/records/bad/stale.record.json; $CLI record lint packages/fixtures/records/bad/high-no-killswitch.record.json; $CLI record lint packages/fixtures/records/bad/auth-unbounded.record.json; for r in $OUT/records/*.record.json; do $CLI record lint "$r" \|\| exit 1; done` | first three exit 1; loop exits 0 |
| S5 | Records are Cosign-signed. `$CLI record sign --key` writes `<id>.record.sigstore.json`; `$CLI record verify --pubkey` exits 0; the gate refuses to start on a record with a missing or non-verifying signature. | `R=$(ls $OUT/records/*.record.json \| head -1); $CLI record verify "$R" --pubkey $OUT/keys/cosign.pub && cp "$R" out/probe/unsigned.record.json && $CLI gate serve --record out/probe/unsigned.record.json --pubkey $OUT/keys/cosign.pub --upstream "$CLI upstream demo" --self-test` | verify exits 0; gate exits 1 with `signature` in stderr |

### F2 · Gate (reference PEP)

| # | Claim | Probe | Pass |
|---|---|---|---|
| S6 | `packages/policy/gate.rego` produces `data.colophon.gate.decision = {effect, rule_ids, reasons}` and, for the shipped inputs, `in-scope`→allow, `unknown-tool`→deny `COL-GATE-UNKNOWN-TOOL`, `scope-expansion`→deny `COL-GATE-SCOPE`, `sandbox-escape`→deny `COL-GATE-SANDBOX`, `data-class`→deny `COL-GATE-DATACLASS`, `destination`→deny `COL-GATE-DESTINATION`, `needs-approval`→escalate `COL-GATE-APPROVAL`. | `for f in packages/fixtures/gate-input/*.json; do echo "$f $(opa eval -f raw -d packages/policy/gate.rego -i $f 'concat(\":\", [data.colophon.gate.decision.effect, concat(\",\", data.colophon.gate.decision.rule_ids)])')"; done` | each line shows the effect and rule ID named above |
| S7 | Every deny in every demo trace carries ≥1 `rule_ids` entry and ≥1 `reasons` entry whose `field` names a Record field. | `jq -c 'select(.effect=="deny") \| select((.rule_ids\|length)==0 or (.reasons\|length)==0 or (.reasons[0].field\|length)==0)' $OUT/*/trace/*.jsonl \| wc -l` | `0` |
| S8 | `opa test packages/policy -v` passes ≥ 20 tests covering allow, deny, and escalate for every rule ID; `opa fmt --list packages/policy` prints nothing. | `opa test packages/policy -v 2>&1 \| grep -c PASS; opa fmt --list packages/policy` | count ≥ 20; second command prints nothing |
| S9 | Changing one line in `gate.rego` changes a demo decision with zero `.ts` changes. | `bun tests/policy-flip.ts` | prints `FLIP: sandbox-escape deny -> allow` and `ts-diff: 0` |
| S10 | If OPA errors (here: the gate policy path points at a file that does not exist), the gate denies every call with `COL-GATE-OPA-ERROR` and logs the cause; it never falls open. | `COLOPHON_GATE_POLICY=/nonexistent/gate.rego $CLI agent run --scenario packages/fixtures/scenarios/evidence-reader.yaml --record $OUT/records/evidence-reader.record.json --pubkey $OUT/keys/cosign.pub --out out/probe/opa-fail >/dev/null; jq -r '.effect+":"+.rule_ids[0]' out/probe/opa-fail/trace/*.jsonl \| sort -u` | exactly `deny:COL-GATE-OPA-ERROR` |
| S11 | No TypeScript file names a gate effect except the fail-closed deny in `packages/gate/eval.ts` (`COL-GATE-OPA-ERROR`) and the adapters' translation of a foreign PEP's own verdict field; no line keys allow/deny/escalate on a tool name, path, scope, data class, or destination. | `bun tests/no-ts-verdicts.ts` | exit 0; last line ends in `: 0` |
| S12 | The gate is an MCP stdio server: `tools/list` returns exactly the record's tool names present upstream; the calls that reached the upstream are exactly the allowed decisions (same tool, same redacted arguments, same count), so no refused call was forwarded. | `$CLI agent run --scenario packages/fixtures/scenarios/evidence-reader.yaml --record $OUT/records/evidence-reader.record.json --pubkey $OUT/keys/cosign.pub --out out/probe/mcp --list-tools; jq -c 'select(.effect=="allow") \| [.tool, .args_redacted]' out/probe/mcp/trace/*.jsonl \| sort > out/probe/allowed.txt; jq -cS '[.tool, .args]' out/probe/mcp/upstream-calls.jsonl \| sort > out/probe/reached.txt; diff out/probe/allowed.txt out/probe/reached.txt && echo same` | `tools:` line lists exactly the five record tools; `same` printed |

### F3 · Decision and Trace

| # | Claim | Probe | Pass |
|---|---|---|---|
| S13 | Every trace line validates against `packages/schema/decision.schema.json` with fields `source, effect, rule_ids, reasons, tool, args_sha256, ts, prev_sha256, this_sha256`, and the trace writer rewrites a head commitment after every decision (`<trace>.head.json`: line count and last hash), so removing lines from the end is detectable. | `$CLI trace verify $OUT/evidence-reader/trace/*.jsonl; head -c 0 $OUT/evidence-reader/trace/*.jsonl.head.json` | exit 0; output contains `schema: ok` and `sealed: yes` |
| S14 | `this_sha256` is SHA-256 over the RFC 8785 form of the line without `this_sha256`; `prev_sha256` links lines; `$CLI trace verify` exits 1 naming the line index after any single byte changes. | `cp $OUT/evidence-reader/trace/*.jsonl out/probe/t.jsonl; sed -i.bak '3s/"effect":"/"effect":"x/' out/probe/t.jsonl; $CLI trace verify out/probe/t.jsonl` | exit 1; output contains `line 3` |
| S15 | The synthetic credential from the evidence-reader scenario (passed under a `token` key) appears nowhere under `out/demo`; its SHA-256 does (secret-named keys and secret-shaped values are stored as `sha256:<hex>` commitments). | `T=$(grep -o 'FAKE-DEMO-CREDENTIAL[A-Za-z0-9-]*' packages/fixtures/scenarios/evidence-reader.yaml \| head -1); (grep -r "$T" out/demo \|\| true) \| wc -l; grep -rl "$(printf %s "$T" \| shasum -a 256 \| cut -c1-64)" out/demo \| wc -l` | first `0`; second ≥ 1 |

### F4 · Demo

| # | Claim | Probe | Pass |
|---|---|---|---|
| S16 | `bun run demo` from a fresh clone exits 0 in under 90 s with no network, writes only under `out/`, and prints `SIGNATURE: <path>` for each packet. | `time bun run demo; (git status --porcelain \| grep -v '^?? out/' \|\| true) \| wc -l` | exit 0; < 90 s; `0` |
| S17 | The evidence-reader trace contains four distinct deny rule IDs — `COL-GATE-UNKNOWN-TOOL`, `COL-GATE-SCOPE`, `COL-GATE-SANDBOX`, `COL-GATE-DATACLASS` — and the notifier trace contains `COL-GATE-DESTINATION` plus at least one allowed `mail.send` and one allowed `fs.write`. | `jq -r 'select(.effect=="deny").rule_ids[]' $OUT/evidence-reader/trace/*.jsonl \| sort -u; jq -r 'select(.effect=="allow").tool' $OUT/notifier/trace/*.jsonl \| sort -u; jq -r 'select(.effect=="deny").rule_ids[]' $OUT/notifier/trace/*.jsonl \| sort -u` | the four IDs; `fs.write` and `mail.send`; `COL-GATE-DESTINATION` |
| S18 | `bun run demo` twice in a row succeeds. | `bun run demo && bun run demo` | both exit 0 |
| S19 | When `cosign sign-blob` fails over a bundle manifest (records signed, session run, bundle created, then the manifest signature fails), the demo exits 1, stderr names cosign, the failed bundle has no `manifest.sigstore.json`, and no `SIGNATURE:` line is printed. | `COLOPHON_COSIGN_BIN=$PWD/tests/fake-cosign-signfail.sh bun run demo --out out/probe/signfail > out/probe/sf.out 2> out/probe/sf.err; echo "exit=$?"; grep -c '^SIGNATURE:' out/probe/sf.out; grep -ci cosign out/probe/sf.err; ls out/probe/signfail/evidence-reader/bundle/manifest.json out/probe/signfail/evidence-reader/trace/*.jsonl \| wc -l; ls out/probe/signfail/*/bundle/*.sigstore.json 2>/dev/null \| wc -l` | `exit=1`; `0`; ≥ 1; `2` (bundle and trace exist: the failure happened after packaging); `0` |

### F5 · Evidence, Catalog, Report

| # | Claim | Probe | Pass |
|---|---|---|---|
| S20 | Evidence ids are the SHA-256 of the canonical payload; the store rejects a duplicate id and an item whose `sha256` does not match its payload. | `bun test tests/evidence.test.ts && grep -c 'duplicate\|mismatch' tests/evidence.test.ts` | 0 fail; count ≥ 2 |
| S21 | `packages/catalog/controls.yaml` defines ≥ 8 controls, each with `id, title, intent, framework_refs, phase (assess\|verify), check`, covering declaration completeness, gate fail-closed, deny-has-rule-and-field, trace integrity, citation guard, manifest completeness (verify phase), signature present (verify phase), narrative states limits. | `bun tests/catalog-shape.ts` | prints `controls: N` with N ≥ 8 and `themes: 8/8` |
| S22 | `report/assessment-results.json` validates against the vendored OSCAL 1.2.3 Assessment Results schema. | `$CLI report validate $OUT/evidence-reader/bundle/report/assessment-results.json` | exit 0; output contains `oscal-version: 1.2.3` |
| S23 | Every observation's `relevant-evidence.href` resolves to a back-matter resource whose `rlinks[0].href` is a bundle-relative path whose SHA-256 matches `rlinks[0].hashes[0].value`. `$CLI bundle verify` walks claim → file → hash, re-verifies the bundled Record's signature, and checks every gate decision's `record_sha256` is that Record. | `$CLI bundle verify $OUT/evidence-reader/bundle --pubkey $OUT/keys/cosign.pub` | exit 0; output contains `rlinks: ` with a count ≥ 1, `unresolved: 0`, and `bound to verified record` |
| S24 | Citation guard: a report that would cite an evidence id not in the store fails before writing with `CitationError`, and no file is written. | `bun test tests/citation.test.ts && grep -c 'refuses' tests/citation.test.ts` | 0 fail; count ≥ 1 |
| S25 | `narrative.md` contains a proves / does-not-prove table, the sentence `Custody is provable. Judgment is not.`, and never the word `vacuous`. | `grep -c 'Judgment is not' $OUT/evidence-reader/bundle/report/narrative.md; grep -ci 'does not prove' $OUT/evidence-reader/bundle/report/narrative.md; grep -ci vacuous $OUT/evidence-reader/bundle/report/narrative.md` | ≥ 1; ≥ 1; `0` |
| S26 | For a shipped breach trace (an out-of-scope call executed), the report marks the gate control `not-satisfied`. | `$CLI report --trace packages/fixtures/traces/breach.jsonl --record $OUT/records/evidence-reader.record.json --out out/probe/breach; jq '[."assessment-results".results[].findings[] \| select(.target.status.state=="not-satisfied")] \| length' out/probe/breach/report/assessment-results.json` | ≥ 1 |

### F6 · Bundle and signature

| # | Claim | Probe | Pass |
|---|---|---|---|
| S27 | `bundle create` writes `manifest.json` last with per-file `sha256`, `bytes`, and a `root_sha256`; it refuses a non-empty output directory. | `jq '.root_sha256, (.files\|length)' $OUT/evidence-reader/bundle/manifest.json; $CLI bundle create --from $OUT/evidence-reader/stage --out $OUT/evidence-reader/bundle` | hash printed, count ≥ 4; second command exits 1 |
| S28 | `bundle verify` exits 1 naming the file after any single byte change, any added file, or any removed file. | `rm -rf out/probe/b out/probe/b2 out/probe/b4 && cp -r $OUT/evidence-reader/bundle out/probe/b && printf x >> out/probe/b/report/narrative.md; $CLI bundle verify out/probe/b --pubkey $OUT/keys/cosign.pub; cp -r $OUT/evidence-reader/bundle out/probe/b2 && touch out/probe/b2/extra.txt; $CLI bundle verify out/probe/b2 --pubkey $OUT/keys/cosign.pub; cp -r $OUT/evidence-reader/bundle out/probe/b4 && rm out/probe/b4/session.json; $CLI bundle verify out/probe/b4 --pubkey $OUT/keys/cosign.pub` | all three exit 1; outputs name `narrative.md`, `extra.txt`, and `session.json` |
| S29 | `bundle sign --key` writes `manifest.sigstore.json` (Cosign 3 bundle format); `bundle verify --pubkey` exits 0 on it and exits 1 when the signature file is missing. | `ls $OUT/evidence-reader/bundle/manifest.sigstore.json && rm -rf out/probe/b3 && cp -r $OUT/evidence-reader/bundle out/probe/b3 && rm out/probe/b3/manifest.sigstore.json; $CLI bundle verify out/probe/b3 --pubkey $OUT/keys/cosign.pub` | file listed; verify exits 1 naming `manifest.sigstore.json` |
| S30 | `bundle verify --out <dir>` writes a second OSCAL AR (`verification-results.json`) outside the bundle with findings for the verify-phase controls (manifest complete, signature present), valid against the same schema. | `$CLI bundle verify $OUT/evidence-reader/bundle --pubkey $OUT/keys/cosign.pub --out out/probe/vr && $CLI report validate out/probe/vr/verification-results.json && jq -r '."assessment-results".results[].findings[].title' out/probe/vr/verification-results.json` | exit 0; titles include `COL-08` and `COL-09` |

### F7 · Adapters

| # | Claim | Probe | Pass |
|---|---|---|---|
| S31 | The claude-hook adapter normalizes a fixture JSONL of PreToolUse events into chained Decisions and the demo runs the same catalog to a signed, verifiable bundle for it. | `$CLI normalize claude-hook packages/fixtures/claude-hook/session.jsonl --out out/probe/ch && $CLI trace verify out/probe/ch/trace/*.jsonl && $CLI bundle verify $OUT/claude-hook/bundle --pubkey $OUT/keys/cosign.pub` | all exit 0; trace `source` is `claude-hook` |
| S32 | The aws-config adapter is an interface plus a fixture reader shaped like CloudTrail `LookupEvents`, IAM `GetRolePolicy`, and S3 `GetBucketEncryption`; it emits Decisions (AccessDenied → deny) and evidence; no AWS SDK is a dependency and no live client exists. | `$CLI normalize aws-config packages/fixtures/aws --out out/probe/aws && jq -r '.effect' out/probe/aws/trace/*.jsonl \| sort \| uniq -c; jq -r '(.dependencies + .devDependencies)\|keys[]' package.json \| grep -c aws; grep -rn 'LiveAws\|@aws-sdk' packages \| wc -l` | both `allow` and `deny` present; `0`; `0` |
| S38 | The agentcore-dogwood adapter normalizes fixture AgentCore/Dogwood AuthorizeAction events (approve-before-act, out-of-scope, rate-limit, simple allow) into chained Decisions; missing/unknown decisions deny fail-closed (`AGENTCORE-NO-DECISION`); the demo seals a verifiable packet; no AWS SDK and no live CloudWatch/EventBridge client. | `$CLI normalize agentcore-dogwood packages/fixtures/agentcore-dogwood/session.jsonl --out out/probe/ac && $CLI trace verify out/probe/ac/trace/*.jsonl && $CLI bundle verify $OUT/agentcore-dogwood/bundle --pubkey $OUT/keys/cosign.pub && $CLI normalize agentcore-dogwood packages/fixtures/agentcore-dogwood/no-decision.jsonl --out out/probe/ac-fc` | exits 0; source `agentcore-dogwood`; deny rule ids include `DW-APPROVE-BEFORE-ACT`, `DW-OUT-OF-SCOPE`, `DW-RATE-LIMIT`; fail-closed fixture names `AGENTCORE-NO-DECISION`; no AWS SDK |

### F9 · Club Finding export

| # | Claim | Probe | Pass |
|---|---|---|---|
| S39 | `colophon export finding` maps sealed Decisions to GRC Eng Club `finding.schema.json` v1 (resource `ai_agent_session`, Colophon COL-* evaluations, no invented SCF ids); the demo writes Finding JSON **beside** the AgentCore/Dogwood packet (not inside the Cosign bundle); `$CLI export finding validate` exits 0 on those files. | `$CLI normalize agentcore-dogwood packages/fixtures/agentcore-dogwood/session.jsonl --out out/probe/ac-find && $CLI export finding --from out/probe/ac-find --out out/probe/findings && $CLI export finding validate out/probe/findings/*.finding.json && $CLI export finding validate $OUT/agentcore-dogwood/findings/*.finding.json` | all exit 0; output names `finding.schema.json v1.0.0`, `ai_agent_session`, `ac-roe-0001`; demo finding includes `COL-01`; findings dir is not listed in the packet manifest |

### F8 · Docs and CI

| # | Claim | Probe | Pass |
|---|---|---|---|
| S33 | README states the one-sentence product, the design rule, a proves / does-not-prove table, exactly the two commands, and points at STATUS.md. | `grep -c 'Custody is provable. Judgment is not.' README.md; grep -c 'bun install && bun run demo' README.md; grep -c 'bundle verify' README.md; grep -c 'STATUS.md' README.md` | all ≥ 1 |
| S34 | STATUS.md has one row per claim S1–S39 and A1–A3; every `done` row names the probe run and the session date. | `grep -cE '^\| (S[0-9]+\|A[0-9]+) ' STATUS.md` | `42` |
| S35 | DECISIONS.md records only decisions made in this repo, each with a rationale; it contains no operator brief. | `grep -ci 'operator brief' DECISIONS.md; grep -c '^### ' DECISIONS.md` | `0`; ≥ 8 |
| S36 | `bun test` passes and `bun run typecheck` exits 0. | `bun test 2>&1 \| tail -3; bun run typecheck` | 0 fail; exit 0 |
| S37 | `.github/workflows/ci.yml` pins Bun and Cosign 3.x, runs `bun install --frozen-lockfile`, typecheck, `bun test`, `opa test`, `bun run demo`, `bun tests/probes.ts`, asserts a `*.sigstore.json` exists, and runs `bundle verify`; signing in CI is keyless with a pinned certificate identity and issuer. | `grep -E 'cosign-installer\|cosign-release\|bun-version\|frozen-lockfile\|opa test\|bun run demo\|probes.ts\|sigstore.json\|bundle verify\|certificate-identity' .github/workflows/ci.yml \| wc -l` | ≥ 9 |

### Anti-claims (must stay false)

| # | Claim | Probe | Pass |
|---|---|---|---|
| A1 | No signing fallback: no code path continues after a failed sign; `signed` is never written by a code path that did not verify. | `grep -rnE 'signed\.ok\|fallback\|stopgap' packages --include=*.ts \| wc -l` | `0` |
| A2 | No LLM provider SDK and no AWS SDK in `package.json`. | `jq -r '(.dependencies + .devDependencies)\|keys[]' package.json \| grep -ciE 'openai\|anthropic\|aws-sdk\|google-ai\|bedrock'` | `0` |
| A3 | `gitleaks` finds no secret in the tree (demo keys live under `out/`, which is gitignored and allowlisted). | `gitleaks detect --no-git --config .gitleaks.toml --exit-code 1 -v 2>&1 \| tail -2` | `no leaks found` |

## 5. Demo scenario

Two agents. **evidence-reader** (risk `high`, tools `repo.list`, `repo.read_settings`, `fs.read`, `auth.request_scopes` bounded by `max_scopes: ["repo:read"]`, `sandbox.write_paths: ["out/evidence-reader/"]`) is asked for branch-protection evidence on two in-scope repos. Along the way it attempts: `mail.send` (undeclared tool → `COL-GATE-UNKNOWN-TOOL`), `auth.request_scopes` for `admin:org` (→ `COL-GATE-SCOPE`), `fs.write` of a synthetic token to `/tmp/gh-token.json` (→ `COL-GATE-SANDBOX`), and `fs.read` of a file labeled `secret` when the tool allows only `public,internal` (→ `COL-GATE-DATACLASS`). **notifier** (risk `medium`, tools `mail.send` bounded to `*@acme.example`, `fs.write` bounded to `out/notifier/`) sends one in-domain notice and writes one file inside its sandbox, then attempts `mail.send` to `ops@evil.example` (→ `COL-GATE-DESTINATION`).

The narrative for each packet lists what was asked, what was attempted, what was refused with which rule and which Record field, what the packet proves, and what it does not.
