/**
 * The human-readable half of the report. Says what was asked, what was
 * attempted, what was refused and why, what the packet proves, and what it
 * does not. Never says a control "holds vacuously": an unexercised control is
 * reported not-satisfied by the catalog and the narrative repeats that.
 */
import type { ControlResult, StagedPolicy } from "../catalog/checks.ts";
import { bindingReasons, contextReasons, explanationReasons, type Decision } from "../normalize/decision.ts";
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
  /** Policy files staged under policy/ in this packet; empty when nothing binds the verdicts to a policy text. */
  policies?: StagedPolicy[];
};

function primaryArg(d: Decision): string {
  const a = d.args_redacted ?? {};
  for (const k of ["path", "to", "url", "repo", "scopes", "org", "file_path", "command", "action", "bucketName", "roleName"]) {
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
  if (n.source === "colophon-hook") {
    lines.push("Colophon was the policy enforcement point here, running as a Claude Code PreToolUse hook: every tool call was decided by `gate.rego` through OPA before Claude Code ran it, and the hook rewrote no tool input. Tool names are the declared projections of Claude Code's (`Write` → `fs.write`, paths relative to the session's working directory); each decision carries the Claude tool name and a hash of the full input as context. An `ask` records that the human was asked, not what the human chose.");
    lines.push("");
  }
  const gatePolicy = (n.policies ?? []).find((p) => p.role === "gate");
  // Keyed on the decisions, never on the staged file alone: a staged policy
  // with unbound decisions beside it is reported as exactly that.
  const unboundToGate = gatePolicy ? n.decisions.filter((d) => d.policy_sha256 !== gatePolicy.sha256) : [];
  if (gatePolicy && unboundToGate.length === 0 && n.decisions.length > 0) {
    lines.push(`Policy bound: every decision carries \`policy_sha256\` \`${gatePolicy.sha256}\`, the hash of the \`gate.rego\` bytes that decided it, and that file is staged in this packet as \`${gatePolicy.path}\`. A verifier compares the two; the control results below were computed at build time against that same text, and are not re-evaluated at verification time.`);
    lines.push("");
  } else if (gatePolicy) {
    lines.push(`Policy staged, not fully bound: \`${gatePolicy.path}\` (sha256 \`${gatePolicy.sha256}\`) is in this packet, but ${unboundToGate.length} of ${n.decisions.length} decisions do not carry that hash (${unboundToGate.slice(0, 3).map((d) => `call ${d.call_index ?? "?"} on \`${d.tool}\`${d.policy_sha256 ? "" : ", no policy_sha256"}`).join("; ")}${unboundToGate.length > 3 ? "; …" : ""}). COL-11 below reads not-satisfied for that reason.`);
    lines.push("");
  }
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
      if (pep.policies?.length) {
        const stagedById = new Map((n.policies ?? []).filter((p) => p.role === "declared").map((p) => [p.id, p]));
        lines.push(`- Policies in force, declared on the signed Record and staged in this packet (hash over the staged statement file):`);
        for (const p of pep.policies) {
          const s = stagedById.get(p.id);
          lines.push(`  - \`${p.id}\` (${p.kind}) → ${s ? `\`${s.path}\`` : "not staged"}, sha256 \`${p.sha256}\`.`);
        }
        if (pep.policy_set_hash) lines.push(`- Policy set commitment (sha256 over the sorted per-policy hashes, newline-joined): \`${pep.policy_set_hash}\`.`);
        lines.push("- A refusal under the PEP's default deny cites no permit because none matched; the permits that existed are the files above.");
      } else {
        lines.push("- No policies are declared on the Record, so this packet cannot show which policy text produced these decisions (COL-11 below).");
      }
    } else {
      lines.push("- No Record `pep` binding was present; decisions are assessed as a foreign PEP replay.");
    }
    lines.push("- Colophon does not call CloudWatch or EventBridge. Captured APPLICATION_LOGS JSONL is an ingest path; session id comes from sidecar/CLI metadata, not the log body. `aws-config` (CloudTrail/IAM) is a separate infrastructure-PEP adapter.");
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
    const r0 = bindingReasons(d)[0] ?? d.reasons[0];
    lines.push(`| ${d.call_index ?? ""} | \`${d.tool}\` ${primaryArg(d)} | ${d.effect} | ${d.rule_ids.join(", ")} | \`${r0?.field ?? ""}\` | ${JSON.stringify(r0?.value ?? "")} |`);
  }
  lines.push("");
  if (denies.length > 0) {
    lines.push("## What was refused, and why");
    lines.push("");
    for (const d of denies) {
      // Only binding reasons are bounds. The PEP's own words are quoted as
      // they were; context (principal, request id, flags) is listed, not
      // rendered as something the value "fell outside".
      const said = explanationReasons(d).map((r) => `The PEP said: "${String(r.value)}".`);
      const bounds = bindingReasons(d).map((r) => `Bound by \`${r.field}\`; the value \`${JSON.stringify(r.value)}\` fell outside it.`);
      const ctx = contextReasons(d).map((r) => `${r.field.split(".").pop()}=${JSON.stringify(r.value)}`);
      lines.push(`- Call ${d.call_index ?? "?"} \`${d.tool}\` ${primaryArg(d)}: refused under ${d.rule_ids.map((r) => `\`${r}\``).join(", ")}. ${[...said, ...bounds].join(" ")}${ctx.length ? ` (context: ${ctx.join(", ")})` : ""}`);
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
  // The proves row follows COL-11's own result when it is present (pass 2), and the
  // decisions themselves before it exists (pass 1): the row never outruns the control.
  const col11 = n.results.find((r) => r.control.check === "policy-bound");
  const declaredPolicies = n.record?.declaration.pep?.policies ?? [];
  const boundByDecisions = n.decisions.length > 0 && (gatePolicy ? unboundToGate.length === 0 : declaredPolicies.length > 0 && (n.policies ?? []).filter((p) => p.role === "declared").length === declaredPolicies.length);
  const policyBound = col11 ? col11.state === "satisfied" : boundByDecisions;
  if (policyBound) {
    lines.push("| Each verdict is bound, by hash, to the policy text staged in this packet under `policy/`. | That the verdicts were re-evaluated against that text at verification time; the control results are the build-time results, attributable to that text. |");
  } else if ((n.policies ?? []).length > 0) {
    lines.push("| (Policy text is staged under `policy/`, but not every verdict is bound to it; COL-11 reads not-satisfied.) | Which policy text produced the unbound verdicts. |");
  } else {
    lines.push("| (No policy text is staged in this packet; COL-11 reads not-satisfied.) | Which policy text produced these verdicts. |");
  }
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
