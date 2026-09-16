# Security

Colophon's whole claim is that a packet fails closed: a tampered file, a broken chain, a missing signature, or a credential that survived redaction is a refusal, not a warning. A bug in that behaviour is a security bug.

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Do not open a public issue for anything that could let a packet verify when it should not, let a secret reach a trace, or let a refused call be recorded as allowed.

Expect an acknowledgement within a week. Fixes land with a probe in `SPEC.md` that would have caught the report, so the class stays closed.

## In scope

- `bundle verify`, `trace verify`, or `record verify` returning 0 on altered, added, removed, or unsigned content.
- Any path by which a credential-shaped value reaches a sealed trace, evidence item, report, or bundle.
- A TypeScript code path that decides allow/deny (verdicts belong to `packages/policy/gate.rego`).
- The gate forwarding a refused call upstream.
- Demo or CI writing outside `out/`, or CI signing without the pinned certificate identity and issuer.

## Out of scope

- Whether a Declaration's policy is the right policy. Custody is provable; judgment is not.
- Actions that never passed through the PEP. The packet proves what the PEP saw, not that everything went through it.
- The signer's trustworthiness. A Cosign signature proves who sealed the bytes, not that they should be trusted.
- The demo key pair (`out/demo/keys`, password `colophon-demo`) protects nothing and is not meant to.
