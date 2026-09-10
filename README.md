# Colophon

**Colophon emits a signed session packet: operator Declaration → signed Record → Decisions from a policy enforcement point (the reference MCP gate or a foreign adapter) → hash-chained Trace → content-addressed Evidence → control findings as OSCAL Assessment Results → Sigstore/Cosign-signed bundle a stranger can verify with only the directory and a public key.**

The gate is the reference microphone. The packet is the product.

> **Custody is provable. Judgment is not.**

## Two commands

```
bun install && bun run demo
bun run colophon bundle verify out/demo/evidence-reader/bundle --pubkey out/demo/keys/cosign.pub
```

The demo needs `bun`, `opa`, `cosign` (3.x), and `jq` on the path. It runs offline after install: two declared agents are gated through the MCP gate, two foreign PEP fixtures (a Claude Code hook log, a CloudTrail export) are normalized, and four packets are signed with a throwaway local key pair and verified. It exits 1 if signing fails. It prints `SIGNATURE: <path>` only after `bundle verify` passed.

A stranger with `cosign` alone:

```
cosign verify-blob --key out/demo/keys/cosign.pub \
  --bundle out/demo/evidence-reader/bundle/manifest.sigstore.json \
  --insecure-ignore-tlog out/demo/evidence-reader/bundle/manifest.json
```

(`--insecure-ignore-tlog` because the local demo signs offline with no transparency-log entry. CI signs keyless against the public Sigstore instance and verifies with a pinned certificate identity and issuer; no flag there.)

## What the packet proves, and what it does not

| proves | does not prove |
|---|---|
| The signer produced these bytes (Cosign signature over the manifest). | That the signer is trustworthy or authorized. |
| No file in the bundle was altered, added, or removed after signing (manifest hashes). | That the files are complete relative to what happened outside the PEP. |
| The decisions occurred in this order and were not edited after the fact (hash chain). | That every action the agent took passed through this PEP. |
| Each refusal cites a rule and the Record field that bound it. | That the policy is the right policy. |
| Every cited evidence item exists in the store with the stated hash. | That the evidence is sufficient or the checks are the right checks. |
| The catalog checks ran deterministically over this evidence. | Correctness of any human or model judgment about the agent. |

## What is in a packet

```
bundle/
  manifest.json              every file, sha256, bytes, root hash — written last
  manifest.sigstore.json     Cosign 3 bundle over manifest.json
  records/                   the signed Record the gate bound (gate sessions)
  trace/<session>.jsonl      hash-chained Decisions
  evidence/<sha256>.json     content-addressed evidence, cited or not
  catalog/controls.yaml      the controls evaluated (stands in for an assessment plan)
  report/assessment-results.json   OSCAL 1.2.3; findings → observations → back-matter rlinks → files + hashes
  report/narrative.md        what was asked, attempted, refused, proven, not proven
  session.json
```

`colophon bundle verify` walks manifest → signature → OSCAL rlinks → files → hashes → trace chains, and with `--out` writes a second OSCAL AR for the two verify-phase controls (manifest completeness, signature) outside the bundle, because a bundle cannot attest to its own signature.

## Vocabulary

**Declaration**: operator-authored YAML, unsigned intent. **Record**: the Declaration canonicalized (RFC 8785), hashed, Cosign-signed, and bound by the gate at startup. **Decision**: one PEP-agnostic verdict (`allow` / `deny` / `escalate`, rule ids, reasons naming the binding field). **Trace**: chained Decisions. **Evidence**: content-addressed payloads. **Bundle**: the directory. **Packet**: bundle plus signature. There is no "Agent Card"; an A2A card may be cited as `identity.a2a_card_uri` and nothing more.

## Adapters

| adapter | status |
|---|---|
| `colophon-gate` | live in the demo: MCP stdio PEP, verdicts only from `packages/policy/gate.rego` via OPA |
| `claude-hook` | fixture: PreToolUse hook events → Decisions → same catalog, signed packet |
| `aws-config` | interface + fixture reader only (CloudTrail LookupEvents, GetRolePolicy, GetBucketEncryption). No SDK, no live client. |

## Status

Every claim, its probe, and whether the probe ran from a fresh clone: [`SPEC.md`](SPEC.md) defines them, [`STATUS.md`](STATUS.md) reports them, [`DECISIONS.md`](DECISIONS.md) records the choices made here. Nothing in this repository claims a live AWS collector, an OWASP contribution, in-toto co-authorship, or any certification.

## License

MIT.
