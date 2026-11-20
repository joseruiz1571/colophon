# Colophon and Proof-of-Control: a requirement-level crosswalk

> **Status: draft for the maintainer's review.** Written by a coding agent against the code at the commit that adds this file; the grades are not the maintainer's until he has read them.

**Standard:** LF Decentralized Trust / Advanced AI Society, *Proof-of-Control*, Working Draft v0.1, read at repository `LFDT-ProofOfControl/ov-poc-standard` commit `54a7bc6` (2026-10-29), 127 requirements. Requirement ids are checked against that commit's checklist, vendored in [`packages/fixtures/proof-of-control/`](../packages/fixtures/proof-of-control/SOURCE.md).
**Subject:** the Colophon session packet, as specified in [`SPEC.md`](../SPEC.md), Colophon 0.1.0.
**Date of this analysis:** 2026-11-15. **Stage:** Self-Declared (C10.1.1).

**Tier claimed:** 2

> **The one-line result.** A Colophon packet is **Tier 2 (Attestation)** evidence under C8. Anyone can re-verify its bytes, its hash chain and its signature, but one party, the operator who ran the enforcement point and holds the signing key, must be trusted for the evidence to mean anything. It is not Proof-of-Control, and nothing in this repository says it is.

---

## 1. What is being graded, and what is not

Proof-of-Control grades evidence of what an agent did at an action boundary. Colophon sits at that boundary in two forms: the reference MCP gate and the Claude Code hook. Both decide through the same Rego policy and write the same Decision records. This crosswalk grades the packet those two produce.

| In scope | Out of scope, with reason |
| --- | --- |
| The gate (`packages/gate/server.ts`), the hook (`packages/hook/index.ts`), the trace, the bundle manifest, the Cosign signature and `bundle verify` | **Foreign enforcement points.** For AgentCore and Dogwood, Colophon normalizes someone else's decisions after the fact. It does not intercept, so the C7.1 rows do not describe those packets. |
| The claim: *"these Decisions were recorded in this order by this enforcement point, bound to this signed Record and this policy text, and the bytes are unaltered since signing."* | **Whether the policy is the right policy,** and any judgment about the agent. Custody is provable. Judgment is not (C7.5.1). |
| | **Actions that never reached the enforcement point.** The README says the packet does not prove that every action passed through it. |

**Domains claimed (C10.1.2): none.** The C4.1 rows are graded because the gate is an authorization enforcement point, not because an Authorization claim is made. The words "Proof-of-Control" appear in this repository only as analysis or explicit non-claim (C8.1.4).

---

## 2. The claims, graded

### 2.1 Claim register (C8.1.1 to C8.1.3)

| # | Claim | Evidence | Mechanism | Parties that must be trusted | Tier |
| --- | --- | --- | --- | --- | --- |
| PC-1 | The files in a packet are byte-identical to what the builder wrote. | `manifest.json` | per-file SHA-256, a root hash, and a completeness check that fails on any added, removed or altered file | SHA-256; the verifier implementation | 2 |
| PC-2 | The manifest was produced by a named signer and not altered since. | `manifest.sigstore.json` | Cosign `sign-blob` over the manifest bytes | key mode: the operator's key custody. Keyless mode: the OIDC provider, the Fulcio certificate authority, the Rekor log | 2 |
| PC-3 | The Decisions were not edited, reordered or truncated after the packet was sealed. | `trace/<session>.jsonl` and its head commitment | hash chain over the RFC 8785 form of each Decision; a head commitment of line count and last hash; both covered by PC-1 and PC-2 | as PC-1 and PC-2 | 2 |
| PC-4 | The trace holds every Decision the enforcement point made, and the enforcement point was the unmodified one. | the trace | none beyond the operator's process writing it | the operator | 1 |
| PC-5 | Each Colophon verdict came from the policy text staged in the packet. | `policy_sha256` on each Decision; `policy/gate.rego` in the packet | the enforcement point hashes the policy bytes on disk at each call; `bundle verify` asserts the hash against the staged file | the operator: the stamp is written by the operator's own process | 1 |
| PC-6 | Keyless mode only: the manifest signature was entered in a public transparency log at a log-asserted time. | the log entry inside `manifest.sigstore.json` | `cosign verify-blob` verifies the entry carried in the bundle | the log operator's key, clock and honesty | 2 |

C8.1.2's single-trusted-party rule caps PC-1, PC-2 and PC-3 at Tier 2. PC-6 does not lift them: a log entry carried in a bundle shows inclusion under the log's key, and this repository verifies neither independent monitoring nor consistency with later log heads. Whether log-recorded certificate issuance lifts a keyless signer above the line is an open working-group question (the binary-threshold note in C8, Appendix D issue 6).

### 2.2 Trust-assumption disclosure (C7.4.1, C10.2.1, C10.2.2)

Categories from the C10.2.2 draft set.

| Assumption | Subject | Category | Applies to |
| --- | --- | --- | --- |
| SHA-256 is second-preimage- and collision-resistant | SHA-256 | Mathematical | PC-1, PC-2, PC-3, PC-5 |
| The signature scheme is sound | Cosign's signing scheme | Mathematical | PC-2, PC-6 |
| The signing key is held only by the operator (key mode) | the operator's key custody | Implementation | PC-2 |
| The OIDC provider honestly attests the workflow identity (keyless mode) | GitHub Actions OIDC | Vendor | PC-2, PC-6 |
| Fulcio issues certificates only to authenticated identities; Rekor is append-only (keyless mode) | the Sigstore public instance | Vendor · Distributed | PC-2, PC-6 |
| The verifier and runtime implement the documented checks | cosign, this repository, Bun, OPA | Implementation | all |
| The operator ran an unmodified gate or hook, and routed the agent's tool calls through it | the operator | Implementation | PC-4, PC-5 |
| The trace was not rewritten between its last append and the signature | the operator's machine | Implementation | PC-3 |

Every mechanism in §2.1 has a line here. That is the C7.4.1 reconciliation.

---

## 3. Requirement by requirement

State is one of **met**, **partly met**, **not met**. Level is the standard's own. Every row names the file, probe or verifier line that shows it.

### C4.1 Authorization at the action boundary

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 4.1.1 | 1 | met | The grant is the signed Record: tools, scopes, sandbox paths, data classes and `review_due`. The gate refuses to start unless the Record's hashes recompute, its signature verifies and lint passes, and lint refuses a Record past `review_due` (`packages/policy/record.rego`). The Record is staged in the packet and every Decision carries its hash as `record_sha256`. |
| 4.1.2 | 1 | partly met | *Downgraded after a second-vendor read and narrowed by a probe: in the MCP gate the Record is bound and linted once, when the process starts, and `decide` does not re-lint per call, so a gate that crosses `review_due` keeps allowing calls (probed: startup lint refuses a past-due Record with `COL-REC-STALE`, while `decide` on that same Record returns allow; the actual midnight crossing was simulated, not waited for). The Claude Code hook is not affected: each call is its own process and `bindRecord` runs on every call (`packages/hook/index.ts`). COL-03 and S7 inspect denials only.* Every call is decided by `packages/policy/gate.rego` and the Decision names the rule ids and the Record field that bound it, for allows as well as denies (control `COL-03`, probe S7). |
| 4.1.3 | 3 | partly met | *Downgraded after a second-vendor read: the sandbox check is a string-prefix test (`packages/policy/gate.rego`) and the hook normalizes paths lexically, so a symlink through a permitted path is admitted (probed: a write to a path through a link inside `out/evidence-reader/` that points outside the project returned allow, and the same path resolves outside the sandbox; the policy layer was tested, not Claude Code's Write tool or a real upstream); S12 runs one demo scenario against synthetic tools.* A deny or escalate is returned to the agent and never forwarded (`packages/gate/server.ts`); the Decision carries the tool, `args_sha256` and a redacted view of the arguments (probe S12). |
| 4.1.4 | 2 | partly met | The argument digest is stored as `args_sha256`. Arguments are checked against the Record's scope, sandbox, data-class and destination fields, not validated against a registered tool schema. |
| 4.1.5 | 2 | not met | Colophon issues and holds no credentials. Nothing in `packages/gate/server.ts` scopes the upstream's credentials per task. |
| 4.1.6 | 2 | not met | An escalate becomes a Claude Code `ask` (`packages/hook/index.ts`). The human's answer, their identity and what they were shown are not recorded. |
| 4.1.7 | 2 | not met | The policy input is the Record, the call and a context of session id and call index (`packages/gate/eval.ts`). No state from earlier calls is carried, so a composed sequence is not evaluated as a path. |
| 4.1.8 | 2 | met | For the same reason: tool outputs never enter the policy input, so nothing a tool returns can raise what a later call is allowed (`packages/gate/eval.ts`). |

### C5.1 and C6.1, where the packet touches them

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 5.1.1 | 1 | partly met | Every Decision carries `session_id` and `record_sha256`, and the Record names the agent and its `owner` (`packages/schema/decision.schema.json`). There is no per-action principal identifier. |
| 6.1.2 | 1 | partly met | Tool, argument digest and timestamp are recorded for every call that reaches the enforcement point. The result status recorded is the verdict, not the tool's result (`packages/schema/decision.schema.json`). |

### C7.1 Generation at the action boundary

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.1.1 | 3 | partly met | The gate is a separate process between the agent and the upstream tool server (`packages/gate/server.ts`). Nothing removes the agent's other paths to tools, and the README says so. |
| 7.1.2 | 3 | not met | One Decision per call, written at the verdict (`packages/trace/trace.ts`). No during or after record, and no signature per record: the packet is signed once. |
| 7.1.3 | 3 | partly met | The gate appends the Decision before it forwards the call (`packages/gate/server.ts`). The append is a synchronous write, not a durable one: nothing forces it to disk first. |
| 7.1.4 | 3 | not met | No attested environment, bound capability or attested egress. The gate forwards over an ordinary pipe (`packages/gate/server.ts`). |
| 7.1.5 | 1 | partly met | *Downgraded after a second-vendor read: the generated findings (`packages/catalog/checks.ts`) and the README call allowed Decisions "executed calls", but the Decision is written before the forward and no result is appended, so the packet does not show a call executed. The wording needs fixing before this is met.* Tier 2 is claimed, and the proves / does-not-prove table in `README.md` states that the packet does not prove every action passed through the enforcement point. |

### C7.2 Contemporaneous

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.2.1 | 1 | partly met | The Decision is written in the call's own handler, before the forward, with the time of the verdict as `ts` (`packages/gate/server.ts`). The effect itself leaves no record. |
| 7.2.2 | 3 | partly met | Key mode: no outside time source. Keyless mode: one transparency-log entry per packet, at signing (`.github/workflows/ci.yml`). No anchoring interval is defined. |

### C7.3 Tamper-evident

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.3.1 | 2 | partly met | Each Decision's `this_sha256` covers its canonical form and `prev_sha256` links it to the one before; an edit, insert or reorder fails `trace verify` naming the line (probe S14). Verification runs when a trace is resumed and when a packet is verified, not on a schedule. |
| 7.3.2 | 3 | not met | The signing key is the operator's, or in keyless mode the operator's own workflow identity (`packages/bundle/sign.ts`). No custody the operator cannot reach. |
| 7.3.3 | 3 | not met | Nothing checks that two relying parties were shown the same history: `packages/bundle/verify.ts` verifies one packet against itself. |
| 7.3.4 | 3 | not met | The trace is a linear chain (`packages/trace/trace.ts`). Showing that one Decision is present means replaying the chain; there is no inclusion proof. |
| 7.3.5 | 3 | not met | `packages/bundle/manifest.ts` writes one root hash per packet. No root is published, and there is no consistency proof between roots. |

### C7.4 and C7.5

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.4.1 | 1 | partly met | *Downgraded after a second-vendor read: PC-6 depends on the log's clock, which §2.2 does not list, and PC-3's dependence on the signature is not carried in §2.2.* §2.2 of this document, reconciled against §2.1. |
| 7.5.1 | 1 | met | Every Decision field is an identifier, a digest, a timestamp or a verdict with its rule ids (`packages/schema/decision.schema.json`). The report in the packet states which deterministic checks ran; it asserts nothing about correctness. |
| 7.5.2 | 1 | partly met | `README.md` and the narrative in every packet say what is and is not proven. There is no documented legal or compliance claims review; single maintainer. |

### C7.6 Custody and resilience

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.6.1 | 2 | not met | A failure to write the trace denies the call but raises no alert and writes no secondary log (`packages/hook/index.ts`). |
| 7.6.2 | 2 | met | Chaining is the equivalent the requirement allows: a removed Decision breaks `prev_sha256`, and the head commitment of line count and last hash catches truncation at the end (`packages/trace/trace.ts`, verifier line `chain intact, head commitment matches`). One trace covers one session; nothing links session N to session N+1. |
| 7.6.3 | 4 | partly met | The gate appends before it forwards, so a failed append stops the call, and the hook denies when the trace is unusable (`packages/hook/index.ts`). No probe breaks the evidence store to demonstrate it. |
| 7.6.4 | 2 | not met | A trace is a file on the operator's disk (`packages/trace/trace.ts`). No access control of Colophon's own, and reads are not recorded. |
| 7.6.5 | 1 | not met | No retention period is stated in `SPEC.md` or carried in the packet, and none is configured. |
| 7.6.6 | 3 | not met | Keyless mode anchors once per packet, at signing (`.github/workflows/ci.yml`). No interval is declared and nothing alerts on a missed one. |

### C7.7 Interoperable

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 7.7.1 | 2 | partly met | *Downgraded after a second-vendor read: Decisions are schema-validated, but the manifest and trace head are read with `JSON.parse` and a type cast, not a runtime schema.* `packages/schema/decision.schema.json` covers every Decision field, and `trace verify` validates every line against it (verifier line `schema: ok`). |
| 7.7.2 | 2 | partly met | Digests are over the RFC 8785 form (`packages/schema/canonical.ts`), and the schema states what `this_sha256` covers. The manifest signature covers the manifest bytes as written; the manifest document has no canonical form of its own. Colophon's canonicalizer agrees with the standard's two canonical-form vectors (`tests/poc-canonical.test.ts`, S60). |
| 7.7.3 | 2 | not met | The algorithm is named in the field name (`args_sha256`), not carried with the value, and the verifier has no rule for a digest under another algorithm. The schema does reject uppercase hex. |
| 7.7.4 | 3 | partly met | Tamper cases are probed (S14, S28) and the standard's canonical vectors pass (S60). Colophon publishes no positive and negative vector set of its own. |
| 7.7.5 | 2 | not met | Trace lines are read with `JSON.parse`, which keeps the last of two duplicate keys (`packages/trace/trace.ts`). |

### C8 Tier placement and mechanism fit

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 8.1.1 | 1 | met | §2.1 assigns a Tier to every claim. |
| 8.1.2 | 1 | partly met | *Downgraded after a second-vendor read: PC-1 names SHA-256 and the verifier but not the public key or identity a verifier must also trust, and PC-2 does not say how that key is authenticated.* §2.1 names the trusted parties per claim; each Tier is consistent with them. |
| 8.1.3 | 1 | met | Operator-signed claims are registered at Tier 2 or below (§2.1). |
| 8.1.4 | 1 | partly met | The words are used only as analysis or non-claim (§1). The documented claims review the requirement also asks for does not exist (see 7.5.2). |
| 8.2.1 | 1 | met | §2.1 maps each claim to one mechanism and the fact it evidences; no mechanism is offered for a domain. |
| 8.2.2 | 1 | met | The signature is mapped to byte integrity after signing (PC-2), never to runtime behaviour; the runtime claims (PC-4, PC-5) are registered at Tier 1 for that reason (§2.1). |

### C10 Conformance and disclosure

| Req | L | State | Colophon |
| --- | --- | --- | --- |
| 10.1.1 | 1 | met | Self-Declared, stated at the top of this document and in `SPEC.md` (F13). |
| 10.1.2 | 1 | met | No domains claimed (§1). |
| 10.1.3 | 1 | partly met | *Downgraded after a second-vendor read: §3 asserts authorization, non-forwarding and startup-enforcement facts that §2.1 does not register, and the self-test stream in the packet is not named as evidence.* Each claim in §2.1 names its evidence file in the packet. |
| 10.1.4 | 1 | partly met | System, claims, mechanisms, Tiers and the disclosure are in §1 and §2. Per-claim evidence properties are not tabulated. |
| 10.1.5 | 1 | met | Working Draft v0.1 at commit `54a7bc6`; 2026-11-15. |
| 10.1.6 | 1 | met | The §1 boundary table, with reasons for each exclusion. |
| 10.1.7 | 2 | not met | This statement is prose (`docs/proof-of-control.md`). The packet is machine-readable; the statement is not. |
| 10.2.1 | 1 | partly met | *Downgraded after a second-vendor read: §2.2's "Applies to" column does not carry inherited assumptions per claim (PC-2's signer-key authentication, PC-3's signature dependency, PC-6's clock).* §2.2, one line per mechanism in §2.1. |
| 10.2.2 | 2 | met | Each line in §2.2 carries a category from the draft set. |

---

## 4. What would change the claim

Nothing above moves Colophon past Tier 2, and four gaps are structural: key custody the operator cannot reach (7.3.2), a record at each of three points with its own signature (7.1.2), inclusion proofs (7.3.4), and a mediated effect channel (7.1.4). Two are small and local: an algorithm tag on digest values (7.7.3) and a parser that refuses duplicate keys (7.7.5).

One thing a Tier 3 claim would need (C8.1.5) is built, and true from the first tagged release: a stranger can verify a published packet with no operator credentials. Each release carries one keyless-signed packet, `packet-evidence-reader.tar.gz` (`.github/workflows/release.yml`, S58). After unpacking it:

```
cosign verify-blob --bundle bundle/manifest.sigstore.json \
  --certificate-identity-regexp '^https://github.com/joseruiz1571/colophon/\.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  bundle/manifest.json
```

No release exists at the commit that adds this file, so that run has not happened yet.
