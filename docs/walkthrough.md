# One refusal, six artifacts

The whole product on one page. The notifier agent may mail `*@acme.example`. It tries `ops@evil.example`. Here is that one deny, followed from the line that bound it to the signature a stranger checks. Every value below is from one `bun run demo` run; session ids carry a timestamp, so your hashes will differ and your structure will not.

```
bun install && bun run demo
B=out/demo/notifier/bundle
```

## 1. The Declaration line that bound it

`packages/fixtures/declarations/notifier.yaml`:

```yaml
  - name: mail.send
    data_access: none
    data_classes: []
    destinations: ["*@acme.example"]
```

`colophon record build` canonicalizes this (RFC 8785), hashes it, and Cosign signs it. The gate refuses to start unless the signature verifies. The Record's `canonical_sha256` in this run: `b0ef2393c92ba…`.

## 2. The Rego rule that fired

`packages/policy/gate.rego`, the only place a verdict is decided:

```rego
denies contains {"rule_id": "COL-GATE-DESTINATION", "reason": {"field": "tools[].destinations", "value": dest}} if {
	tool_known
	count(object.get(tool, "destinations", [])) > 0
	count(destination_keys) == 1
	dest := destination_of(args)
	not destination_allowed(dest)
}
```

No TypeScript file decides allow or deny; `tests/no-ts-verdicts.ts` fails the build if one does.

## 3. The trace line, hash-chained

`$B/trace/notifier-session-<ts>.jsonl`, line 3:

```json
{"source":"colophon-gate","effect":"deny","rule_ids":["COL-GATE-DESTINATION"],
 "reasons":[{"field":"tools[].destinations","value":"ops@evil.example"}],
 "tool":"mail.send","args_sha256":"661b1ada…","args_redacted":{"to":"ops@evil.example","subject":"Weekly notice","body":"See attached"},
 "session_id":"notifier-session-20260916032940","call_index":2,
 "record_sha256":"b0ef2393c92ba…","ts":"2026-09-16T03:29:41.370Z",
 "prev_sha256":"218d3bbe…","this_sha256":"e89fa4fe…"}
```

`record_sha256` binds the line to the Record from step 1. `prev_sha256` links to line 2. `this_sha256` covers the line. A `.head.json` beside the trace commits the line count and last hash, so dropping lines from the end is detectable too. Change one byte and the chain names the line:

```
sed -i 's/ops@evil.example/ops@acme.example/' trace/*.jsonl
bun packages/cli/main.ts trace verify trace/*.jsonl
# error: chain broken at line 3: this_sha256 mismatch: recorded e89fa4fe…, computed 30c3c947…
```

## 4. The OSCAL observation that cites it

`$B/report/assessment-results.json` (OSCAL 1.2.3 Assessment Results). Control COL-03, "Every refusal names its rule and its binding field", is a finding; its observation cites an evidence item; the back-matter resource points at the file and its hash:

```
finding      COL-03 … — satisfied        related-observations → 3097379d-…
observation  3097379d-…  "Deterministic check over evidence 6e2435a2… (trace)"   relevant-evidence → #0b968bc5-…
resource     0b968bc5-…  rlinks[0].href = evidence/6e2435a2b7b9….json
                          rlinks[0].hashes[0] = sha256 0267c6dc71e7…
```

`shasum -a 256 $B/evidence/6e2435a2b7b9….json` prints `0267c6dc71e7…`. That evidence item is the trace itself, content-addressed: its id is the SHA-256 of its canonical payload. Citing an id that is not in the store throws `CitationError` before anything is written.

## 5. The narrative row a human reads

`$B/report/narrative.md`:

```
| 2 | `mail.send` to="ops@evil.example" | deny | COL-GATE-DESTINATION | `tools[].destinations` | "ops@evil.example" |

- Call 2 `mail.send` to="ops@evil.example": refused under `COL-GATE-DESTINATION`.
  Bound by `tools[].destinations`; the value `"ops@evil.example"` fell outside it.

| COL-03 | Every refusal names its rule and its binding field | **satisfied** | 1 refusals, each with a rule id and a binding field. … |
```

Same document also carries the proves / does-not-prove table. It never says a control holds vacuously: a session with no refusals reports COL-03 not-satisfied.

## 6. The manifest and the signature a stranger checks

`$B/manifest.json` lists every file with its SHA-256 (16 files in this run, root hash `49320830…`), written last. `manifest.sigstore.json` is a Cosign 3 bundle over it.

```
cosign verify-blob --key out/demo/keys/cosign.pub \
  --bundle $B/manifest.sigstore.json --insecure-ignore-tlog $B/manifest.json
# Verified OK

bun packages/cli/main.ts bundle verify $B --pubkey out/demo/keys/cosign.pub
# record: notifier.record.json ok (hashes recompute, signature verifies)
# trace: notifier-session-….jsonl ok (3 decisions, chain intact, head commitment matches, bound to verified record)
# verified: out/demo/notifier/bundle
```

The tampered copy from step 3 fails here as well: `NOT VERIFIED: … (2 failures)`, the chain and the manifest hash.

## What that proves, and what it does not

The signer produced these bytes. Nothing in the bundle changed after signing. The decisions happened in this order. This refusal cites the rule and the Record field that bound it. The evidence it cites exists at the stated hash. The checks ran deterministically.

It does not prove the signer should be trusted, that every action went through the gate, that `*@acme.example` was the right bound, or anything about the agent's judgment. Custody is provable. Judgment is not.
