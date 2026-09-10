# Decisions

Only decisions made in this repository, by the operator who commissioned the build or by the builder with a stated rationale. Where the brief was ambiguous, the conservative fail-closed option was taken and is recorded here. No decision below is attributed to an operator statement that was not actually made; the operator's prompt for this build is the one page that named the product sentence, the layout, the Decision type, the demo, the controls, and the done criteria. Everything else is the builder's call.

### D1 · Greenfield layout, single package
The brief prescribes `packages/*`. Rationale: one root `package.json` with relative imports between `packages/*` directories, rather than Bun workspaces. Workspaces would add per-package manifests with no consumer yet. `$CLI` is `bun packages/cli/main.ts`.

### D2 · Autonomy level is a CSA-style L0–L5 enum
The brief says "map to CSA-style L0–L5 if easy; otherwise a documented enum". Rationale: the enum is `L0`–`L5` with each level's operational meaning in the schema description (L0 no autonomy; L1 assistive; L2 supervised, per-action approval; L3 delegated within bounds, human on the loop; L4 bounded autonomous, exception-only human; L5 fully autonomous). Both demo agents are `L3`. The mapping to any published CSA table is by intent of each level, not a citation.

### D3 · The Record is the Declaration plus provenance, and it is Cosign-signed
Rationale: the brief lists the Record's required fields; all of them live under `declaration` verbatim, and the Record adds `record_type`, `record_version`, `declaration_sha256`, `canonical_sha256`, `created_at`. Canonicalization is RFC 8785 (implemented in `packages/schema/canonical.ts` for the value space used: sorted keys, no whitespace, JSON number serialization). The gate refuses to start unless the Record's hashes recompute, its `<id>.record.sigstore.json` verifies against the presented key or identity, and record lint passes. Fail closed at bind time, not at first call.

### D4 · Data classes are labels on the call, enforced against the tool's allowed classes
Ambiguity: a gate cannot classify payload content it has not fetched. Rationale: any tool with `data_access` other than `none` must carry a `data_class` argument, and it must be one the tool is allowed to touch; an unlabeled read or write is refused (`COL-GATE-DATACLASS`, value `data_class not stated`). This makes the control honest about what it enforces: the agent's stated intent against the Declaration. The narrative and the proves table say so.

### D5 · Four rule ids on the evidence-reader, a fifth on the notifier
Rationale: the brief wants four distinct rule ids from four out-of-scope attempts. `evidence-reader` hits `COL-GATE-UNKNOWN-TOOL` (undeclared `mail.send`), `COL-GATE-SCOPE` (`admin:org` beyond `max_scopes: ["repo:read"]`), `COL-GATE-SANDBOX` (`fs.write` to `/tmp/gh-token.json` outside `out/evidence-reader/`), and `COL-GATE-DATACLASS` (`fs.read` labeled `secret` on a tool allowed `public,internal`). `notifier` hits `COL-GATE-DESTINATION` (`mail.send` to `ops@evil.example` outside `*@acme.example`). Each agent also has allowed calls that exercise the same bounds from the inside (a write inside the sandbox, an in-domain mail), so no control holds for lack of traffic.

### D6 · The one TypeScript effect is deny
The brief: verdicts come only from Rego. Rationale: `packages/gate/eval.ts` names exactly one effect, `deny` with `COL-GATE-OPA-ERROR`, when OPA cannot run, exits non-zero, returns no value, or returns a malformed verdict. That is a fail-closed safety gate, not policy. The Rego side has its own `default decision := deny` for the same reason. The probe for S11 greps for allow/deny branches keyed on tool, path, scope, or class in TypeScript and expects none.

### D7 · OPA error probe uses a policy-path override, not a broken binary
Rationale: pointing `COLOPHON_OPA_BIN` at `/bin/false` breaks record lint at startup, so the gate refuses to start and no trace exists to inspect (also fail-closed, but it does not exercise the per-call path). `COLOPHON_GATE_POLICY=/nonexistent/gate.rego` breaks only gate evaluation: every call is denied with `COL-GATE-OPA-ERROR` and the trace shows it. The startup self-test uses the same nonexistent path to record fail-closed evidence for control COL-02.

### D8 · Rego negation gotcha, recorded so it is not reintroduced
`not is_array(args.scopes)` never fires when `args.scopes` is undefined: the compiler hoists the undefined reference out of the negation and the rule body fails before `not` runs. Fixed with helper rules (`scopes_stated if is_array(args.scopes)` then `not scopes_stated`), same for `path_stated`, `dataclass_stated`, `has_to`. Found by the OPA test suite, which is why it has 34 tests.

### D9 · Cosign 3.x offline signing needs an empty signing config
Cosign 3.1.3 defaults to the new bundle format and a TUF signing config that demands a transparency log; `--tlog-upload=false` is rejected, and so is the legacy `.sig` route without a signing config. Rationale: `cosign signing-config create --no-default-fulcio --no-default-oidc --no-default-rekor --no-default-tsa` yields a config with no services; `sign-blob --key --bundle --signing-config` then signs offline and writes a Cosign 3 bundle (`application/vnd.dev.sigstore.bundle...`). Verification of a key-mode bundle needs `--insecure-ignore-tlog` because there is no log entry to check; the README says so. Keyless in CI uses the default public instance with no such flag. Probed in a scratch directory before any code was written: sign exit 0, verify exit 0, tampered blob verify exit 1.

### D10 · OSCAL 1.2.3, vendored, validated with ajv in draft-07 mode
The brief prefers 1.1.2 if 1.2 is painful. Rationale: the NIST 1.2.3 JSON schema is draft-07 and compiles under ajv with `strict: false`; a minimal document validated in a scratch probe, so the newest release is used and vendored at `packages/report/vendor/`. The AR carries one finding per control, one observation per cited evidence item, and back-matter resources whose `rlinks` point at bundle-relative paths with SHA-256 hashes of the file bytes. `import-ap` points at the shipped catalog resource, since Colophon has no separate assessment plan.

### D11 · Verify-phase controls get a second AR, outside the bundle
Ambiguity: "manifest completeness evaluated after the bundle exists" and "signature present" cannot be findings inside a document that is itself covered by the manifest and the signature. Rationale: the catalog marks COL-08 and COL-09 `phase: verify`; the in-bundle AR covers the eight assess-phase controls; `colophon bundle verify --out <dir>` writes `verification-results.json` (same schema, same builder) with those two findings, plus evidence items for the manifest and signature files. A bundle does not attest to its own signature.

### D12 · Unexercised controls are not-satisfied, never vacuous
Rationale: a session with zero refusals cannot show that refusals carry rule ids. COL-03 reports `not-satisfied` with the rationale "not exercised" in that case, and the narrative says the same. Likewise a foreign PEP with no Record gets `not-satisfied` on the Record-dependent controls with the reason stated; the claude-hook and aws-config packets show 5/8 for exactly this reason. This is what "their gate, your packet" honestly looks like.

### D13 · Executed-within-Record is checked by re-evaluating through the policy
Rationale: control COL-05 re-runs every allowed decision's redacted arguments through `gate.rego` and expects allow again; the breach fixture (a sandbox escape recorded as allowed) turns it not-satisfied. This keeps assessment logic out of TypeScript conditionals and reuses the one policy. Redacted arguments keep paths, scopes, destinations, and labels; secret-shaped values are replaced, so re-evaluation of secret-bearing calls sees `[REDACTED]`, which no rule keys on.

### D14 · Demo key pair is generated per run under `out/`, with a fixed non-secret password
Rationale: the local demo needs a key; generating one per run under the gitignored `out/` directory keeps keys out of the tree. `COSIGN_PASSWORD` is the literal `colophon-demo`, which protects nothing and is not meant to. `.gitleaks.toml` allowlists `out/` and the scenario file that carries the synthetic `ghp_FAKE...` token used to prove redaction.

### D15 · Probe runner clones committed HEAD
Rationale: the brief says a claim is done only when its probe ran from a fresh clone. `tests/probes.ts` clones the repository's committed HEAD into a temp directory, installs with `--frozen-lockfile`, runs the demo, then runs every SPEC probe there and writes `out/probes.json`. Uncommitted work is invisible to it by design. STATUS rows are written from that output and cite the HEAD they ran at.

### D16 · Repository not pushed by the builder
Rationale: creating a public remote is outward-facing and was not part of the brief. The CI workflow is written and pinned but has not run; STATUS marks the green-CI half of S37 partial for that reason and says what is needed (push to a GitHub repository with `id-token: write`).

### D17 · Installed nothing
Bun 1.4.0, OPA 1.19.1, Cosign 3.1.3, jq 1.8.2, and gitleaks 8.30.1 were already present on the build machine; CI pins the same Bun, OPA, and Cosign versions and installs gitleaks at the same version.
