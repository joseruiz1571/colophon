# Finding export (GRC Eng Club interop)

Colophon's spine is the **signed agentic receipt** (Declaration → Record → Decisions → Trace → Evidence → OSCAL AR → Cosign packet). This module is an **output speaker** on that Decision stream: it writes [GRC Eng Club](https://github.com/GRCEngClub/claude-grc-engineering) `finding.schema.json` v1 documents so a club `/gap-assessment` can read the same PEP verdicts.

It is not a CloudTrail collector, not a live AWS connector, and not a product pivot. CloudTrail dual-emit is deferred. `packages/adapters/aws-config` stays infrastructure-PEP fixture evidence.

## Three layers

| layer | who | this export |
|---|---|---|
| Detection | CloudWatch spans, metrics, Guardrails | no |
| PEP | AgentCore Gateway + Dogwood, the reference MCP gate, or another adapter | no — we do not enforce |
| Custody | Decision → Trace → packet; Finding JSON is a club-readable projection | yes (projection only) |

The packet remains the source of custody. Findings are interop.

## Schema

Vendored unchanged from upstream at [`finding.schema.json`](finding.schema.json). Provenance: [`SOURCE.md`](SOURCE.md). Do not invent fields.

One Finding = one **resource** + one or more **evaluations**.

- `resource.type` is `ai_agent_session` (the agent/session/PEP boundary, not an S3 bucket).
- `resource.id` is the Colophon `session_id`.
- PEP source (`agentcore-dogwood`, `colophon-gate`, `claude-hook`, `aws-config`) is `resource.pep_source` / `tags.pep` (resource `additionalProperties` is allowed) and `metadata.pep_source`.
- `source` is the club connector id: `colophon` for the reference gate, `colophon-agentcore-dogwood` (etc.) for foreign PEPs.
- `source_version` is this package version (`0.1.0`).

## Evaluations

Two honest layers, both `control_framework: "Colophon"`:

1. **Catalog COL-*** (when assess-phase results are supplied): `satisfied` → `pass`, `not-satisfied` → `fail`. These are the same COL-01…COL-10 ids as `packages/catalog/controls.yaml`. Verify-phase COL-08/COL-09 stay on `bundle verify --out`, not this export.
2. **PEP verdict polarity** (one evaluation per Decision): `allow` → `pass`, `deny` → `fail`, `escalate` → `inconclusive`. `deny`=`fail` means the PEP refused the call, **not** that a catalog control is unmet unless a catalog evaluation also says so. Control ids prefer `COL-*` / `COL-GATE-*` from `rule_ids`; otherwise the PEP-native id (`DW-*`, `AGENTCORE-*`) is kept. Those are not SCF ids.

If both layers are empty, one `inconclusive` `COL-04` evaluation is emitted (fail closed; the schema requires `evaluations.minItems: 1`).

## SCF crosswalk (stub, deferred)

Club gap-assessment prefers SCF. This exporter does **not** emit SCF control IDs. A future crosswalk could join Colophon catalog `framework_refs` (already on each COL-* in `controls.yaml`) through SCF; until that join is maintained, treating `DW-*` or `COL-GATE-*` as SCF is a lie. Do not rip-replace `packages/catalog/controls.yaml` with SCF.

| Colophon | already cited in catalog `framework_refs` | SCF (not emitted) |
|---|---|---|
| COL-01 Declaration completeness | NIST-AI-RMF GOVERN 1.1, NIST-800-53 AC-6 | — |
| COL-02 Gate fails closed | OWASP LLM06, NIST-800-53 AC-6 | — |
| COL-03 Refusal names rule and field | NIST-AI-RMF MEASURE 2.6, NIST-800-53 AU-3 | — |
| COL-04 Trace hash chain | NIST-800-53 AU-9, AU-10 | — |
| COL-05 Executed calls stayed in Record | OWASP LLM06, NIST-AI-RMF MANAGE 2.2 | — |
| COL-10 No credentials in packet | OWASP LLM02, NIST-800-53 SC-28 | — |

## CLI

```
bun packages/cli/main.ts export finding --trace <file> --out <dir> [--record <record.json>] [--source <pep>]
bun packages/cli/main.ts export finding --from <normalize-or-packet-dir> --out <dir>
bun packages/cli/main.ts export finding validate <file>
```

`--from` reads sealed traces under `trace/`, `bundle/trace/`, or `stage/trace/`. Findings are written **beside** the packet (`<packet>/findings/`), never into the Cosign bundle.

## Demo

`bun run demo` still seals five packets. It also writes club-valid Finding JSON next to each packet, including AgentCore/Dogwood: same decisions → receipt + club-readable findings.

```
bun run demo
bun packages/cli/main.ts export finding validate out/demo/agentcore-dogwood/findings/*.finding.json
bun packages/cli/main.ts bundle verify out/demo/agentcore-dogwood/bundle --pubkey out/demo/keys/cosign.pub
```
