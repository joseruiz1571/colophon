# Colophon + mlassure at [un]prompted

Recorded from fresh local fixture verification during generation; opening this document does not run a verifier. [Offline HTML with expandable details](conference-demo.html).

**15 seconds:** An agent tries to mail outside its declared scope. The gate refuses it. A signed packet lets someone else check the recorded evidence. mlassure brings evidence traceability to control assessments.

> Evaluations tell us what happened. Verifiable evidence lets someone else check the claim.

## 1 — The boundary

The notifier fixture calls mail.send through Colophon’s reference MCP gate. OPA evaluates gate.rego against the signed Record; this call is refused before the demo upstream executes it. No real email is sent.

```yaml
  - name: mail.send
    data_access: none
    data_classes: []
    destinations: ["*@acme.example"]
```

```rego
denies contains {"rule_id": "COL-GATE-DESTINATION", "reason": {"field": "tools[].destinations", "value": dest}} if {
	tool_known
	count(object.get(tool, "destinations", [])) > 0
	count(destination_keys) == 1
	dest := destination_of(args)
	not destination_allowed(dest)
}

```

This is the reference Rego gate. Foreign PEPs such as AgentCore Gateway + Dogwood enforce their own policies; Colophon normalizes and seals their decisions. LOG_ONLY records a would-be verdict and does not establish that a call was blocked. This build uses repository fixtures, not a fresh AWS session.

## 2 — The evidence

record_sha256 binds the decision to the Record’s canonical_sha256. policy_sha256 binds it to the gate.rego bytes. prev_sha256 equals the previous decision’s this_sha256. this_sha256 hashes this decision (excluding itself). The signed bundle also covers the trace head’s line count and final hash, so truncation is detectable.

```json
{
  "source": "colophon-gate",
  "effect": "deny",
  "rule_ids": [
    "COL-GATE-DESTINATION"
  ],
  "reasons": [
    {
      "field": "tools[].destinations",
      "value": "ops@evil.example"
    }
  ],
  "tool": "mail.send",
  "args_sha256": "661b1ada64eb581e80095f9150a08dd2c1dfe13010b0a2081dee9b387a4786e4",
  "args_redacted": {
    "to": "ops@evil.example",
    "subject": "Weekly notice",
    "body": "See attached"
  },
  "session_id": "notifier-session-20261027155048",
  "call_index": 2,
  "record_sha256": "fc34215f66130625c3b6915ea7bd6a2458f897d3c886305d34d2359406141642",
  "policy_sha256": "15980e1f0d247bba504001fc0fb521e5b76d994811a8e5ef6994030eb4896acf",
  "ts": "2026-10-27T15:50:49.097Z",
  "prev_sha256": "5cd34b4e3f0db1a0d7324704e6644bb79710a2aa24d83ba9bf596e04e2d599c0",
  "this_sha256": "23ac7a93521260d34ed187eac38e7177e790bfa4773902e30b854b375ecb8132"
}
```

The chain commits to recorded order. It does not independently establish real-world timing or prove that every action was recorded. Before sealing, the chain is not signed; a writer could rebuild it. The signature anchors the sealed packet to a key.

## 3 — The verification

The original passes. An edited trace fails. The unchanged manifest still has a valid signature.

Cosign checks manifest.json. Colophon also checks the listed files, Record signature, policy binding, OSCAL evidence links, and trace chain. The altered copy replaces ops@evil.example with ops@acme.example in the trace without re-signing.

Actual bundle paths (complete):
```text
catalog/controls.yaml
evidence/042d79faf4cef9cc713f594af04619d5c22f78d07494f0b7e40a663a7dad4f58.json
evidence/652976121a6acec4804e0aecc987ade8101d82865aeb9551475a58bd36915fe5.json
evidence/65719e59f989226ea8bb87a974a9cd09b8e1dc239cc9908e3a4e42aec1b17ac1.json
evidence/662570f2c5be48207326a93b9a4531dfaebdf20c3c72e0e5268e34821207bb77.json
evidence/9396f68e8b0506c492110ddc4801e60ef60f16e846ec92c01600ee9c03a4a3ec.json
evidence/9726e00f23f722b42413d40838dfe21f7846c35be0133d68764952987397d527.json
evidence/bf08ca47bd680cc87e75fd41a912580f646e733e40c936df2792602e5782800b.json
evidence/cb5659923c1b9be9426e59d9d122fa753247043607a04b88979246437d212dd4.json
evidence/f4a9416d756a46b80b51868432842c87ba2b92db6fb8c3c72aa0a8d6018872cb.json
manifest.json
manifest.sigstore.json
policy/gate.rego
records/notifier.record.json
records/notifier.record.sigstore.json
report/assessment-results.json
report/narrative.md
session.json
trace/notifier-session-20261027155048.jsonl
trace/notifier-session-20261027155048.jsonl.head.json
```

Cosign exit 0:
```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

Colophon exit 0 (selected lines):
```text
record: notifier.record.json ok (hashes recompute, signature verifies)
trace: notifier-session-20261027155048.jsonl ok (3 decisions, chain intact, head commitment matches, bound to verified record)
policy: notifier-session-20261027155048.jsonl: 3 decisions bound to policy/gate.rego (sha256 15980e1f0d24…)
verified: $RUN/demo/notifier/bundle
```

Tampered copy exit 1 (selected lines):
```text
FAIL manifest: trace/notifier-session-20261027155048.jsonl: sha256 mismatch: manifest 9dd76b889aec413c8eac4b92b3a887fb2430958bb208435933107d015bb3f2a3, file 351f3344ea613a84eb7233607188322f3f33e27006ebe2ca875a3f7f6b0d124d
FAIL trace: notifier-session-20261027155048.jsonl: line 3: this_sha256 mismatch: recorded 23ac7a93521260d34ed187eac38e7177e790bfa4773902e30b854b375ecb8132, computed b25a69dc49e3d59408b6dbcf8ca181d418f22a19b45e55dbded4445449052d71
NOT VERIFIED: $RUN/tampered (2 failures)
```

The local demo uses a disposable key and no transparency-log entry, hence --insecure-ignore-tlog. A recipient must obtain a trusted public key independently; accepting a key supplied by an unknown producer proves no trusted identity. The HTML is a rendering, not a signed packet.

## 4 — The complementary project

Deterministic collectors retrieve fixture evidence into an EvidenceStore. Control pattern tags select code checks, LLM judgment, or human-attestation handling. The citation guard rejects IDs absent from the current store; satisfied and partially-satisfied verdicts must cite evidence. Existing citations establish traceability, not relevance or sound reasoning. The live AWS provider is deferred in this revision.

Recorded conformance fixture (not a fresh LLM assessment):
```json
{
  "controlId": "SI-6(1)",
  "status": "satisfied",
  "confidence": "high",
  "rationale": "Data capture is enabled at 100 percent and an hourly model-quality monitoring schedule is Scheduled against the InService endpoint.",
  "evidenceCited": [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002"
  ],
  "gaps": []
}
```

SC-28: deterministic encryption-at-rest check; no LLM call.
SI-6(1): synthesis of monitoring evidence; LLM judgment.
SA-10: human review; returns insufficient-evidence without an LLM call.

During generation, the citation-guard suite passed; the positive custody fixture passed and the tampered-file fixture failed. Full output is embedded in the HTML.

mlassure bundles report.json, `evidence/<uuid>.json` (all retrieved payloads, cited or not), optional oscal.json and narrative.md, and manifest.json. verify-bundle checks integrity and completeness. Authenticity needs a separate Cosign check over the manifest. These checked-in conformance fixtures are unsigned; no fresh LLM assessment or mlassure signature verification is claimed. The projects are complementary; no automatic Colophon-to-mlassure integration is demonstrated.

## 5 — What this proves

**Evidence integrity:** Manifest hashes and signatures bind the supplied bytes to a key. They do not establish that the evidence is true, complete relative to the outside world, or produced by a trustworthy operator.

**Policy enforcement:** This notifier run exercises the reference gate’s destination refusal. A sealed foreign verdict records what that PEP reported; enforcement depends on that PEP, its mode, and whether the action passed through it.

**Control assessment:** A finding applies a particular check or judgment to available evidence. The citation invariant excludes nonexistent evidence IDs; it cannot establish that the evidence supports the conclusion.

**Behavioral correctness:** Neither project proves the agent is correct, safe in every context, or unable to bypass an unobserved boundary. Those claims require additional evaluation and coverage evidence.

## Reproduce

Generated 2026-10-27T15:50:58+00:00. Colophon source b1ecd7c929f28e35c997ea2ae3c5935712adc0a2; mlassure source dc956322020ed925cefd50081770ca72e9dd3bc6. Executed during generation, recorded when viewed. Paths shortened to $RUN; output otherwise preserved. Sessions, keys, timestamps and hashes vary on regeneration. Only synthetic fixture content is embedded.

```sh
# Prerequisites: Python 3, Bun, OPA, Cosign 3.x (pins in .github/workflows/ci.yml).
# Install only existing locked dependencies in both checkouts:
(cd ../mlassure && bun install --frozen-lockfile)
bun install --frozen-lockfile
python3 scripts/conference-demo.py --mlassure ../mlassure

# Each run prints its own $RUN directory under ignored out/conference-*.
# Substitute that path below. It contains a disposable private key: do not publish it.
RUN=out/conference-REPLACE_WITH_PRINTED_RUN
B="$RUN/demo/notifier/bundle"
cosign verify-blob --key "$RUN/demo/keys/cosign.pub" \
  --bundle "$B/manifest.sigstore.json" --insecure-ignore-tlog "$B/manifest.json"
bun packages/cli/main.ts bundle verify "$B" --pubkey "$RUN/demo/keys/cosign.pub"
bun packages/cli/main.ts bundle verify "$RUN/tampered" --pubkey "$RUN/demo/keys/cosign.pub"
# Last command must exit 1. The generator checks this and the named failure reasons.
```

- [Colophon walkthrough](https://github.com/joseruiz1571/colophon/blob/b1ecd7c929f28e35c997ea2ae3c5935712adc0a2/docs/walkthrough.md)
- [Reference policy](https://github.com/joseruiz1571/colophon/blob/b1ecd7c929f28e35c997ea2ae3c5935712adc0a2/packages/policy/gate.rego)
- [mlassure bundle spec](https://github.com/joseruiz1571/mlassure/blob/dc956322020ed925cefd50081770ca72e9dd3bc6/SPEC.md)
- [mlassure conformance vectors](https://github.com/joseruiz1571/mlassure/blob/dc956322020ed925cefd50081770ca72e9dd3bc6/fixtures/bundles/README.md)
- [mlassure citation guard](https://github.com/joseruiz1571/mlassure/blob/dc956322020ed925cefd50081770ca72e9dd3bc6/src/guard/citation-guard.ts)
