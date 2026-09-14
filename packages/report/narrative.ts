/**
 * The human-readable half of the report. Says what was asked, what was
 * attempted, what was refused and why, what the packet proves, and what it
 * does not. Never says a control "holds vacuously": an unexercised control is
 * reported not-satisfied by the catalog and the narrative repeats that.
 */
import type { ControlResult } from "../catalog/checks.ts";
import type { Decision } from "../normalize/decision.ts";
import type { ColophonRecord } from "../schema/record.ts";

export type NarrativeInput = {
  source: string;
  sessionId: string;
  record: ColophonRecord | null;
  task: string;
  decisions: Decision[];
  results: ControlResult[];
  traceOk: boolean;
  verifyCommand: string;
};

function primaryArg(d: Decision): string {
  const a = d.args_redacted ?? {};
  for (const k of ["path", "to", "url", "repo", "scopes", "org", "file_path", "command", "bucketName", "roleName"]) {
    if (a[k] !== undefined) return `${k}=${JSON.stringify(a[k])}`;
  }
  return "";
}

export function buildNarrative(n: NarrativeInput): string {
  const denies = n.decisions.filter((d) => d.effect === "deny");
  const allows = n.decisions.filter((d) => d.effect === "allow");
  const escalates = n.decisions.filter((d) => d.effect === "escalate");
  const lines: string[] = [];
  lines.push(`# Colophon session packet — ${n.sessionId}`);
  lines.push("");
  lines.push(`**Custody is provable. Judgment is not.**`);
  lines.push("");
  lines.push(`Source (policy enforcement point): \`${n.source}\`. ${n.record ? `Bound Record: \`${n.record.declaration.name}\` (sha256 \`${n.record.canonical_sha256}\`), owner ${n.record.declaration.owner}, risk tier ${n.record.declaration.risk_tier}, autonomy ${n.record.declaration.autonomy_level}.` : "No Record is bound: decisions come from a foreign PEP and are assessed as-is."}`);
  lines.push("");
  if (n.source === "agentcore-dogwood" || n.record?.declaration.pep) {
    const pep = n.record?.declaration.pep;
    lines.push("## Declared rules of engagement (foreign PEP)");
    lines.push("");
    lines.push("This packet is a **signed artifact for agent rules of engagement** (including AI red-team scope assurance): the declared allow/deny boundary as a reconstructible, signed packet. It is also **coding-agent evidence of controls** — which tools were declared, what the PEP allowed or denied — portable for audit sampling, second-party assurance, and vendor attestations.");
    lines.push("");
    lines.push("AgentCore/Dogwood enforce; Colophon makes the decisions portable evidence. Colophon does not reimplement Dogwood in Rego.");
    lines.push("");
    if (pep) {
      lines.push(`- PEP kind: \`${pep.kind}\`. Enforcement mode: **${pep.enforcement_mode}**${pep.enforcement_mode === "LOG_ONLY" ? " (evaluated, not applied at the Gateway — a deny here is a would-deny)" : " (Gateway applied allow/deny)"}.`);
      if (pep.tool_schema_ref) lines.push(`- Agent/MCP tool schema: \`${pep.tool_schema_ref}\`.`);
      if (pep.policy_set_id) lines.push(`- Dogwood policy set: \`${pep.policy_set_id}\`${pep.policy_set_version ? ` version ${pep.policy_set_version}` : ""}${pep.policy_set_hash ? ` (sha256 \`${pep.policy_set_hash}\`)` : ""}.`);
      if (pep.policy_engine_id) lines.push(`- Policy engine: \`${pep.policy_engine_id}\`.`);
      if (pep.gateway_id) lines.push(`- Gateway: \`${pep.gateway_id}\`.`);
    } else {
      lines.push("- No Record `pep` binding was present; decisions are assessed as a foreign PEP replay.");
    }
    lines.push("- Live CloudWatch/EventBridge ingest is not claimed (Phase 4 deferred). `aws-config` (CloudTrail/IAM) is a separate infrastructure-PEP adapter.");
    lines.push("");
  }
  lines.push("## What was asked");
  lines.push("");
  lines.push(n.task);
  lines.push("");
  lines.push("## What was attempted");
  lines.push("");
  lines.push(`${n.decisions.length} tool calls: ${allows.length} allowed, ${denies.length} refused, ${escalates.length} escalated.`);
  lines.push("");
  lines.push("| # | tool | effect | rule ids | binding field | value |");
  lines.push("|---|---|---|---|---|---|");
  for (const d of n.decisions) {
    const r0 = d.reasons[0];
    lines.push(`| ${d.call_index ?? ""} | \`${d.tool}\` ${primaryArg(d)} | ${d.effect} | ${d.rule_ids.join(", ")} | \`${r0?.field ?? ""}\` | ${JSON.stringify(r0?.value ?? "")} |`);
  }
  lines.push("");
  if (denies.length > 0) {
    lines.push("## What was refused, and why");
    lines.push("");
    for (const d of denies) {
      lines.push(`- Call ${d.call_index ?? "?"} \`${d.tool}\` ${primaryArg(d)}: refused under ${d.rule_ids.map((r) => `\`${r}\``).join(", ")}. ${d.reasons.map((r) => `Bound by \`${r.field}\`; the value \`${JSON.stringify(r.value)}\` fell outside it.`).join(" ")}`);
    }
    lines.push("");
  } else {
    lines.push("## What was refused, and why");
    lines.push("");
    lines.push("Nothing was refused in this session. The refusal controls were therefore not exercised and are reported not-satisfied below; this packet does not show that the gate would refuse.");
    lines.push("");
  }
  lines.push("## Control findings");
  lines.push("");
  lines.push("| control | title | state | rationale |");
  lines.push("|---|---|---|---|");
  for (const r of n.results) lines.push(`| ${r.control.id} | ${r.control.title} | **${r.state}** | ${r.rationale.replace(/\|/g, "\\|")} |`);
  lines.push("");
  lines.push("Verify-phase controls (COL-08 manifest completeness, COL-09 signature) are evaluated by `colophon bundle verify` after this bundle is signed; a bundle cannot attest to its own signature.");
  lines.push("");
  lines.push("## What this packet proves, and what it does not");
  lines.push("");
  lines.push("| proves | does not prove |");
  lines.push("|---|---|");
  lines.push("| The signer produced these bytes (Cosign signature over the manifest). | That the signer is trustworthy or authorized. |");
  lines.push("| No file in the bundle was altered, added, or removed after signing (manifest hashes). | That the files are complete relative to what happened outside the PEP. |");
  lines.push(`| The decisions occurred in this order and were not edited after the fact (hash chain${n.traceOk ? ", intact" : ", BROKEN"}). | That every action the agent took passed through this PEP. |`);
  lines.push("| Each refusal cites a rule and the Record field that bound it. | That the policy is the right policy. |");
  lines.push("| Every cited evidence item exists in the store with the stated hash. | That the evidence is sufficient or that the checks are the right checks. |");
  lines.push("| The catalog checks ran deterministically over this evidence. | Correctness of any human or model judgment about the agent. |");
  lines.push("");
  lines.push("Custody is provable. Judgment is not. This packet does not prove the agent behaved well; it proves what the PEP saw, what it decided, and that nobody changed the record since.");
  lines.push("");
  lines.push("## How to verify");
  lines.push("");
  lines.push("```");
  lines.push(n.verifyCommand);
  lines.push("```");
  lines.push("");
  return lines.join("\n");
}
