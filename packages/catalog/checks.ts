/**
 * Deterministic control checks. Each returns satisfied / not-satisfied with a
 * rationale and the evidence ids it cites. Nothing here is a judgment call;
 * every check is a function of the store and the trace.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import type { EvidenceStore } from "../evidence/store.ts";
import { CitationError } from "../evidence/store.ts";
import { decide } from "../gate/eval.ts";
import { bindingReasons, CREDENTIAL_PATTERN, type Decision } from "../normalize/decision.ts";
import type { ColophonRecord } from "../schema/record.ts";
import type { TraceVerification } from "../trace/trace.ts";

export type FrameworkRef = { framework: string; ref: string };
export type ControlDef = {
  id: string;
  title: string;
  intent: string;
  phase: "assess" | "verify";
  check: string;
  falsifier: string;
  framework_refs: FrameworkRef[];
};

export type Catalog = { catalog_version: string; controls: ControlDef[] };

export function loadCatalog(): Catalog {
  const c = YAML.parse(readFileSync(join(import.meta.dir, "controls.yaml"), "utf8")) as Catalog;
  if (!Array.isArray(c.controls) || c.controls.length < 8) throw new Error("catalog malformed or too small");
  return c;
}

export type ControlState = "satisfied" | "not-satisfied";
export type ControlResult = { control: ControlDef; state: ControlState; rationale: string; cited: string[] };

export type AssessContext = {
  source: string;
  record: ColophonRecord | null;
  decisions: Decision[];
  trace: TraceVerification;
  store: EvidenceStore;
  /** Evidence ids the checks may cite. */
  ids: { record?: string; trace: string; summary: string; selftest?: string; narrative?: string };
  narrative: string;
};

/** Same pattern redaction commits on (normalize/decision.ts); a survivor here is a redaction gap, and the packet builder refuses to sign it. */
function scanForSecrets(value: unknown): string | null {
  if (typeof value === "string") return CREDENTIAL_PATTERN.test(value) ? value.slice(0, 8) + "…" : null;
  if (Array.isArray(value)) {
    for (const v of value) {
      const hit = scanForSecrets(v);
      if (hit) return hit;
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) {
      const hit = scanForSecrets(v);
      if (hit) return hit;
    }
  }
  return null;
}

/** Transports where Colophon itself is the PEP (verdicts from gate.rego). Any other source is a foreign PEP whose decisions were normalized. */
export const COLOPHON_PEP_SOURCES = new Set(["colophon-gate", "colophon-hook"]);

type Check = (ctx: AssessContext, control: ControlDef) => ControlResult;

const REQUIRED_DECLARATION_FIELDS = ["owner", "risk_tier", "autonomy_level", "tools", "data_classes", "sandbox", "max_scopes", "kill_switch", "review_due", "control_mappings"] as const;

const checks: Record<string, Check> = {
  "declaration-complete": (ctx, control) => {
    if (!ctx.record || !ctx.ids.record) {
      return { control, state: "not-satisfied", rationale: `No Record is bound to this session (source: ${ctx.source}). A foreign PEP supplies decisions, not a Declaration; completeness cannot be shown.`, cited: [ctx.ids.summary] };
    }
    const d = ctx.record.declaration as unknown as Record<string, unknown>;
    const missing = REQUIRED_DECLARATION_FIELDS.filter((f) => d[f] === undefined || d[f] === null || (Array.isArray(d[f]) && (d[f] as unknown[]).length === 0 && f !== "max_scopes"));
    const sandboxEmpty = ctx.record.declaration.tools.some((t) => t.data_access === "write") && ctx.record.declaration.sandbox.write_paths.length === 0;
    if (missing.length > 0 || sandboxEmpty) {
      return { control, state: "not-satisfied", rationale: `Record ${ctx.record.declaration.name} is incomplete: ${[...missing, ...(sandboxEmpty ? ["sandbox.write_paths (empty with a write tool)"] : [])].join(", ")}.`, cited: [ctx.ids.record] };
    }
    return { control, state: "satisfied", rationale: `Record ${ctx.record.declaration.name} (sha256 ${ctx.record.canonical_sha256.slice(0, 12)}…) carries all ten governed fields: ${ctx.record.declaration.tools.length} tools, sandbox ${JSON.stringify(ctx.record.declaration.sandbox.write_paths)}, max_scopes ${JSON.stringify(ctx.record.declaration.max_scopes)}, kill switch ${ctx.record.declaration.kill_switch.available ? "available" : "NOT available"}, review due ${ctx.record.declaration.review_due}.`, cited: [ctx.ids.record] };
  },

  "gate-fail-closed": (ctx, control) => {
    if (!ctx.ids.selftest) {
      return { control, state: "not-satisfied", rationale: `No fail-closed self-test evidence for source ${ctx.source}; this packet cannot show that the PEP denies undeclared tools or policy-engine failures.`, cited: [ctx.ids.summary] };
    }
    const item = ctx.store.get(ctx.ids.selftest);
    const p = item?.payload as { unknown_tool?: { effect: string; rule_ids: string[] }; opa_error?: { effect: string; rule_ids: string[] } } | undefined;
    const okUnknown = p?.unknown_tool?.effect === "deny" && p.unknown_tool.rule_ids.includes("COL-GATE-UNKNOWN-TOOL");
    const okError = p?.opa_error?.effect === "deny" && p.opa_error.rule_ids.includes("COL-GATE-OPA-ERROR");
    if (okUnknown && okError) {
      return { control, state: "satisfied", rationale: `At session start the gate denied an undeclared tool (COL-GATE-UNKNOWN-TOOL) and denied when the policy engine was pointed at a nonexistent policy (COL-GATE-OPA-ERROR). Both probes ran through OPA on this host.`, cited: [ctx.ids.selftest] };
    }
    return { control, state: "not-satisfied", rationale: `Self-test recorded unknown_tool=${p?.unknown_tool?.effect ?? "missing"}, opa_error=${p?.opa_error?.effect ?? "missing"}.`, cited: [ctx.ids.selftest] };
  },

  "deny-has-rule-and-field": (ctx, control) => {
    const denies = ctx.decisions.filter((d) => d.effect === "deny");
    if (denies.length === 0) {
      return { control, state: "not-satisfied", rationale: `The session contains no deny decisions, so this control was not exercised. It is reported not-satisfied rather than assumed.`, cited: [ctx.ids.trace] };
    }
    const bad = denies.filter((d) => d.rule_ids.length === 0 || bindingReasons(d).length === 0 || bindingReasons(d)[0]!.field.length === 0);
    if (bad.length > 0) {
      return { control, state: "not-satisfied", rationale: `${bad.length} of ${denies.length} deny decisions lack a rule id or a binding field (e.g. call ${bad[0]!.call_index ?? "?"} on ${bad[0]!.tool}).`, cited: [ctx.ids.trace] };
    }
    const ids = [...new Set(denies.flatMap((d) => d.rule_ids))].sort();
    const fields = [...new Set(denies.flatMap((d) => bindingReasons(d).map((r) => r.field)))].sort();
    return { control, state: "satisfied", rationale: `${denies.length} refusals, each with a rule id and a binding field. Rule ids: ${ids.join(", ")}. Fields: ${fields.join(", ")}.`, cited: [ctx.ids.trace] };
  },

  "trace-chain-intact": (ctx, control) => {
    if (ctx.trace.ok && !ctx.trace.sealed) {
      return { control, state: "not-satisfied", rationale: `${ctx.trace.lines} decisions chain correctly but the trace carries no head commitment, so lines removed from its end would be undetectable.`, cited: [ctx.ids.trace] };
    }
    if (ctx.trace.ok) {
      return { control, state: "satisfied", rationale: `${ctx.trace.lines} decisions; every this_sha256 recomputes, every prev_sha256 links to its predecessor, and the head commitment matches the line count and last hash.`, cited: [ctx.ids.trace] };
    }
    return { control, state: "not-satisfied", rationale: `Chain broken: ${ctx.trace.reason}`, cited: [ctx.ids.trace] };
  },

  "allowed-calls-re-evaluate": (ctx, control) => {
    if (!ctx.record) {
      return { control, state: "not-satisfied", rationale: `No Record bound; allowed calls from source ${ctx.source} cannot be re-evaluated against a Declaration.`, cited: [ctx.ids.trace] };
    }
    const allowed = ctx.decisions.filter((d) => d.effect === "allow");
    // A foreign PEP may prefix tool names (AgentCore Gateway: `<Target>___<tool>`);
    // the Record names the projection through pep.tool_name_prefix. The strip is
    // a naming map, never a policy decision: the stripped name is what the
    // Declaration declared, and gate.rego still decides.
    const prefix = ctx.record.declaration.pep?.tool_name_prefix;
    const declaredName = (tool: string) => (prefix && tool.startsWith(prefix) ? tool.slice(prefix.length) : tool);
    const foreign = !COLOPHON_PEP_SOURCES.has(ctx.source);
    const outside: string[] = [];
    for (const d of allowed) {
      const v = decide(ctx.record, { name: declaredName(d.tool), arguments: d.args_redacted ?? {} }, { session_id: d.session_id ?? "reeval", call_index: d.call_index ?? 0 });
      if (v.effect !== "allow") outside.push(`${d.tool}#${d.call_index ?? "?"} → ${v.rule_ids.join(",")}`);
    }
    const scope = foreign
      ? ` This is declaration consistency (the ${ctx.source} decisions re-checked against the bound Record through gate.rego), not a re-run of the foreign policy set${prefix ? `; tool names were mapped through pep.tool_name_prefix "${prefix}"` : ""}.`
      : "";
    if (outside.length > 0) {
      return { control, state: "not-satisfied", rationale: `${outside.length} of ${allowed.length} executed calls fall outside the Record on re-evaluation: ${outside.join("; ")}.${scope}`, cited: [ctx.ids.trace, ...(ctx.ids.record ? [ctx.ids.record] : [])] };
    }
    return { control, state: "satisfied", rationale: `${allowed.length} executed calls re-evaluated against Record ${ctx.record.declaration.name} through gate.rego; all allow again.${scope}`, cited: [ctx.ids.trace, ...(ctx.ids.record ? [ctx.ids.record] : [])] };
  },

  "citation-guard": (ctx, control) => {
    const all = Object.values(ctx.ids).filter((v): v is string => typeof v === "string");
    try {
      ctx.store.assertCited(all);
    } catch (e) {
      if (e instanceof CitationError) return { control, state: "not-satisfied", rationale: e.message, cited: [ctx.ids.summary] };
      throw e;
    }
    return { control, state: "satisfied", rationale: `All ${all.length} evidence ids this report cites resolve in the content-addressed store (${ctx.store.all().length} items).`, cited: [ctx.ids.summary] };
  },

  "narrative-states-limits": (ctx, control) => {
    const hasLimits = /does not prove/i.test(ctx.narrative);
    const hasRule = /Custody is provable\. Judgment is not\./.test(ctx.narrative);
    const cited = ctx.ids.narrative ? [ctx.ids.narrative] : [ctx.ids.summary];
    if (hasLimits && hasRule) return { control, state: "satisfied", rationale: `The narrative carries a proves / does-not-prove table and the custody-versus-judgment rule.`, cited };
    return { control, state: "not-satisfied", rationale: `Narrative lacks ${[!hasLimits && "a does-not-prove statement", !hasRule && "the custody rule"].filter(Boolean).join(" and ")}.`, cited };
  },

  "secrets-redacted": (ctx, control) => {
    // Scan the redacted view AND the reasons: a reason that quotes an argument is
    // the second place a value can hide.
    for (const d of ctx.decisions) {
      const hit = scanForSecrets({ args: d.args_redacted ?? {}, reasons: d.reasons });
      if (hit) return { control, state: "not-satisfied", rationale: `Decision ${d.call_index ?? "?"} (${d.tool}) carries a credential-shaped value (${hit}).`, cited: [ctx.ids.trace] };
    }
    return { control, state: "satisfied", rationale: `${ctx.decisions.length} decisions scanned (redacted arguments and reasons); arguments are stored as SHA-256 plus a redacted view and no credential-shaped value is present.`, cited: [ctx.ids.trace] };
  },
};

/** Run every assess-phase control. Verify-phase controls are evaluated by `colophon bundle verify`. */
export function assess(ctx: AssessContext, catalog: Catalog = loadCatalog()): ControlResult[] {
  return catalog.controls
    .filter((c) => c.phase === "assess")
    .map((c) => {
      const fn = checks[c.check];
      if (!fn) throw new Error(`catalog names an unknown check: ${c.check} (${c.id})`);
      return fn(ctx, c);
    });
}

export function verifyPhaseControls(catalog: Catalog = loadCatalog()): ControlDef[] {
  return catalog.controls.filter((c) => c.phase === "verify");
}
