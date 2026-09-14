# agentcore-dogwood adapter

**AgentCore/Dogwood enforce; Colophon makes the decisions portable evidence.**

This is a foreign PEP adapter. On AWS, Bedrock AgentCore Gateway + Dogwood is the Policy Enforcement Point. Colophon does not reimplement Dogwood in Rego. It normalizes recorded allow/deny decisions into `DecisionDraft`s → hash-chained Trace → Evidence → OSCAL Assessment Results → Sigstore/Cosign bundle.

`packages/adapters/aws-config` stays separate: that adapter is CloudTrail/IAM *infrastructure* PEP evidence, not AgentCore/Dogwood.

Phase 4 (live CloudWatch / EventBridge ingest, AWS SDK) is explicitly deferred. This package is fixture-only: no SDK, no credentials, no network.

## Fixture schema (JSON / JSONL)

One **decision event** per JSONL line (or a JSON array, or `{ "events": [ ... ], "task"?: string, "policy_session_id"?: string }`). Shape is a Colophon-stable projection of:

- AgentCore `AuthorizeAction` span attributes (`aws.agentcore.policy.authorization_decision`, `determining_policies`, `gateway.policy.mode`, …)
- Dogwood CLI `replay --format json` verdicts (`verdict`, `determining_rules`, `index`) plus the tool/session the blog/CLI trace had on the event line

A raw `{ "verdicts": [ ... ] }` Dogwood replay report is **rejected**: it has no tool or policy-session fields. Wrap or emit AuthorizeAction-style events instead.

```json
{
  "event_kind": "AuthorizeAction",
  "ts": "2026-09-14T15:00:01Z",
  "policy_session_id": "ac-roe-0001",
  "tool": "repo.read_file",
  "action": "AgentCore::Action::\"RepoTarget___read_file\"",
  "input": { "path": "src/index.ts", "data_class": "internal" },
  "authorization_decision": "ALLOW",
  "authorization_reason": "permit in-scope read",
  "determining_policies": ["DW-PERMIT-IN-SCOPE-READ"],
  "enforcement_mode": "ENFORCE",
  "gateway_id": "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/roe-red-team",
  "policy_engine_arn": "arn:aws:bedrock-agentcore:us-west-2:123456789012:policy-engine/RoeEngine-abc123xyz0",
  "policy_set_id": "roe-red-team",
  "policy_set_version": "1",
  "policy_set_hash": "<sha256 hex of the policy set bytes>"
}
```

| field | required | notes |
|---|---|---|
| `authorization_decision` (or `verdict` / `decision`) | for a decision event | `ALLOW`/`allow` → allow; `DENY`/`deny` → deny; missing/unknown → **deny fail-closed** (`AGENTCORE-NO-DECISION`) |
| `tool` | yes (else `"unknown-tool"`) | MCP tool name; `action` is kept in reasons |
| `policy_session_id` | yes | Gateway header `x-amzn-bedrock-agentcore-policy-session-id` |
| `input` | no | tool args; hashed + redacted |
| `determining_policies` | no | become `rule_ids`; else `DW-RULE-{n}` from `determining_rules`; else `AGENTCORE-PERMIT` / `AGENTCORE-IMPLICIT-DENY` |
| `enforcement_mode` | no | `ENFORCE` or `LOG_ONLY` — recorded in reasons, never rewritten |
| `event_kind` | no | `response` / `error` (or `history_only: true`) are skipped, matching Dogwood replay |

OTEL-style `attributes["aws.agentcore.policy.*"]` overlays are accepted on the same object so a later CloudWatch span export can reuse this reader.

## ENFORCE vs LOG_ONLY

The Gateway's `policyEngineConfiguration.mode`:

- **ENFORCE** — Dogwood's allow/deny is applied at the Gateway. The packet is evidence of what was blocked or permitted.
- **LOG_ONLY** — Dogwood still evaluates; the Gateway does not block. Colophon records the *evaluated* decision (including would-deny) and names the mode in reasons. A LOG_ONLY deny is not proof the call was stopped.

The signed Record should name the mode (see Declaration `pep`). Colophon does not promote LOG_ONLY to ENFORCE.

## Three layers

| layer | who | Colophon? |
|---|---|---|
| Detection | CloudWatch spans, metrics, Guardrail scores | no (observability) |
| PEP | AgentCore Gateway + Dogwood | no (foreign; we only normalize) |
| Custody | this adapter → Trace → Evidence → OSCAL AR → Cosign | yes |

## CLI (fixture → sealed packet)

Normalize (trace only, same pattern as `claude-hook`):

```
bun packages/cli/main.ts normalize agentcore-dogwood \
  packages/fixtures/agentcore-dogwood/session.jsonl --out out/probe/ac
bun packages/cli/main.ts trace verify out/probe/ac/trace/*.jsonl
```

AJ / community demo — fixture through the full packet (Trace → Evidence → OSCAL AR → Sigstore) and verify:

```
bun install && bun run demo
bun packages/cli/main.ts bundle verify out/demo/agentcore-dogwood/bundle \
  --pubkey out/demo/keys/cosign.pub
bun packages/cli/main.ts export finding validate \
  out/demo/agentcore-dogwood/findings/*.finding.json
```

Same agentic decisions → sealed receipt **and** a GRC Eng Club Finding (`resource.type: ai_agent_session`). The Finding is interop, not a second product. CloudTrail dual-emit is deferred.

The sealed packet is the signed artifact for the agent's rules of engagement and the coding-agent evidence of controls (declared tools + PEP allow/deny). It is not a live AWS session.
