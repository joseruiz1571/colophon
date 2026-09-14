/**
 * Decision stream → GRC Eng Club Finding v1. Output speaker only: does not
 * collect CloudTrail, does not enforce, does not replace the signed packet.
 *
 * Mapping (D26):
 *   Catalog COL-*  satisfied → pass, not-satisfied → fail
 *   PEP verdicts   allow → pass, deny → fail, escalate → inconclusive
 * deny=fail is recorded PEP polarity (the call was refused), not a claim that
 * a Colophon catalog control is unmet. Catalog evaluations carry that claim.
 * No SCF control IDs are emitted.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ControlResult, ControlState } from "../../catalog/checks.ts";
import type { Decision, Effect } from "../../normalize/decision.ts";
import { formatErrors } from "../../schema/validate.ts";
import type { ColophonRecord } from "../../schema/record.ts";
import { FINDING_SCHEMA_VERSION, validateFinding } from "./validate.ts";

export const RESOURCE_TYPE = "ai_agent_session";
export const CONTROL_FRAMEWORK = "Colophon";

export type EvaluationStatus = "pass" | "fail" | "not_applicable" | "inconclusive" | "skipped";
export type EvaluationSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingEvaluation = {
  control_framework: string;
  control_id: string;
  status: EvaluationStatus;
  severity?: EvaluationSeverity;
  message?: string;
  evidence_refs?: string[];
  assessed_at?: string;
};

export type FindingResource = {
  type: string;
  id: string;
  arn: string | null;
  uri: string | null;
  region: string | null;
  account_id: string | null;
  tags?: Record<string, string>;
  pep_source?: string;
  record_sha256?: string;
};

export type FindingDocument = {
  schema_version: typeof FINDING_SCHEMA_VERSION;
  source: string;
  source_version: string;
  run_id: string;
  collected_at: string;
  resource: FindingResource;
  evaluations: FindingEvaluation[];
  raw_attributes?: Record<string, unknown>;
  findings?: {
    id: string;
    title: string;
    severity: EvaluationSeverity;
    description?: string;
    related_control_ids?: string[];
    related_resource_ids?: string[];
  }[];
  metadata?: Record<string, unknown>;
};

export type FindingExportInput = {
  decisions: Decision[];
  sessionId: string;
  /** PEP name as recorded on Decision.source (agentcore-dogwood, colophon-gate, …). */
  source: string;
  collectedAt?: string;
  runId?: string;
  record?: ColophonRecord | null;
  catalogResults?: ControlResult[];
  task?: string;
};

const CONNECTOR_VERSION: string = (JSON.parse(readFileSync(join(import.meta.dir, "../../../package.json"), "utf8")) as { version: string }).version;

const SOURCE_RE = /^[a-z][a-z0-9-]*$/;

/** Stable club connector id. colophon-gate → `colophon`; other PEPs → `colophon-{pep}`. */
export function connectorSource(pep: string): string {
  const slug = pep.trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!slug || slug === "colophon" || slug === "colophon-gate") return "colophon";
  const id = slug.startsWith("colophon-") ? slug : `colophon-${slug}`;
  if (!SOURCE_RE.test(id)) throw new Error(`finding source would not match club pattern: ${id}`);
  return id;
}

function runIdOf(sessionId: string, explicit?: string): string {
  const id = (explicit ?? `colophon-${sessionId}`).trim();
  if (id.length < 8) return `colophon-${id}`.padEnd(8, "0");
  return id;
}

function collectedAtOf(decisions: Decision[], explicit?: string): string {
  if (explicit) return explicit;
  const last = decisions.at(-1)?.ts;
  if (last) return last;
  return new Date(0).toISOString();
}

function statusForEffect(effect: Effect): EvaluationStatus {
  switch (effect) {
    case "allow":
      return "pass";
    case "deny":
      return "fail";
    case "escalate":
      return "inconclusive";
  }
}

function statusForCatalog(state: ControlState): EvaluationStatus {
  return state === "satisfied" ? "pass" : "fail";
}

function catalogSeverity(id: string, state: ControlState): EvaluationSeverity {
  if (state === "satisfied") return "info";
  if (id === "COL-10" || id === "COL-05" || id === "COL-02") return "high";
  return "medium";
}

function pepControlId(d: Decision): string {
  const col = d.rule_ids.find((r) => r.startsWith("COL-"));
  if (col) return col;
  const first = d.rule_ids[0];
  if (first && first.length > 0) return first;
  return "COL-03";
}

function reasonText(d: Decision): string {
  return d.reasons.map((r) => `${r.field}=${JSON.stringify(r.value)}`).join("; ");
}

function decisionMessage(d: Decision): string {
  const polarity =
    d.effect === "allow"
      ? "PEP allowed this call"
      : d.effect === "deny"
        ? "PEP refused this call (verdict polarity; not a catalog COL-* unsatisfied unless a catalog evaluation says so)"
        : "PEP escalated this call; Colophon records the verdict and does not decide";
  return `${polarity}: ${d.tool} [${d.rule_ids.join(", ")}]. ${reasonText(d)}`;
}

function pepSeverity(d: Decision): EvaluationSeverity | undefined {
  if (d.effect === "allow") return "info";
  if (d.effect === "deny") {
    if (d.rule_ids.includes("AGENTCORE-NO-DECISION") || d.rule_ids.includes("COL-GATE-OPA-ERROR")) return "high";
    return "medium";
  }
  return undefined;
}

function catalogEvaluations(results: ControlResult[]): FindingEvaluation[] {
  return results.map((r) => {
    const status = statusForCatalog(r.state);
    const ev: FindingEvaluation = {
      control_framework: CONTROL_FRAMEWORK,
      control_id: r.control.id,
      status,
      severity: catalogSeverity(r.control.id, r.state),
      message: r.rationale,
      evidence_refs: r.cited.map((id) => `evidence:${id}`),
    };
    return ev;
  });
}

function decisionEvaluations(decisions: Decision[]): FindingEvaluation[] {
  return decisions.map((d) => {
    const status = statusForEffect(d.effect);
    const ev: FindingEvaluation = {
      control_framework: CONTROL_FRAMEWORK,
      control_id: pepControlId(d),
      status,
      message: decisionMessage(d),
      evidence_refs: [`decision:${d.this_sha256}`],
      assessed_at: d.ts,
    };
    const sev = pepSeverity(d);
    if (sev) ev.severity = sev;
    return ev;
  });
}

function emptyEvaluations(collectedAt: string): FindingEvaluation[] {
  return [
    {
      control_framework: CONTROL_FRAMEWORK,
      control_id: "COL-04",
      status: "inconclusive",
      message:
        "Export had no decisions and no catalog results; refusing to report pass or fail. Colophon fails closed rather than inventing a vacuous evaluation.",
      assessed_at: collectedAt,
    },
  ];
}

function resourceOf(i: FindingExportInput): FindingResource {
  const pep = i.record?.declaration.pep;
  const tags: Record<string, string> = { pep: i.source };
  if (i.record) {
    tags["agent"] = i.record.declaration.name;
    tags["owner"] = i.record.declaration.owner;
    tags["risk_tier"] = i.record.declaration.risk_tier;
  }
  if (pep?.enforcement_mode) tags["enforcement_mode"] = pep.enforcement_mode;
  if (pep?.kind) tags["pep_kind"] = pep.kind;
  const resource: FindingResource = {
    type: RESOURCE_TYPE,
    id: i.sessionId,
    arn: pep?.gateway_id ?? null,
    uri: `colophon://session/${encodeURIComponent(i.sessionId)}`,
    region: null,
    account_id: null,
    tags,
    pep_source: i.source,
  };
  if (i.record) resource.record_sha256 = i.record.canonical_sha256;
  return resource;
}

function counts(decisions: Decision[]): { allow: number; deny: number; escalate: number } {
  const c = { allow: 0, deny: 0, escalate: 0 };
  for (const d of decisions) c[d.effect]++;
  return c;
}

/**
 * One Finding per session: resource = agent/session/PEP boundary, evaluations =
 * catalog COL-* (when provided) plus one evaluation per Decision.
 */
export function buildFinding(i: FindingExportInput): FindingDocument {
  if (!i.sessionId || i.sessionId.trim().length === 0) throw new Error("finding export: session_id is required (resource.id)");
  const collected_at = collectedAtOf(i.decisions, i.collectedAt);
  const catalog = i.catalogResults ?? [];
  const evaluations = [...catalogEvaluations(catalog), ...decisionEvaluations(i.decisions)];
  const c = counts(i.decisions);
  const related = [...new Set(evaluations.map((e) => e.control_id))];
  const doc: FindingDocument = {
    schema_version: FINDING_SCHEMA_VERSION,
    source: connectorSource(i.source),
    source_version: CONNECTOR_VERSION,
    run_id: runIdOf(i.sessionId, i.runId),
    collected_at,
    resource: resourceOf(i),
    evaluations: evaluations.length > 0 ? evaluations : emptyEvaluations(collected_at),
    raw_attributes: {
      pep_source: i.source,
      session_id: i.sessionId,
      decision_count: i.decisions.length,
      ...c,
      deny_rule_ids: [...new Set(i.decisions.filter((d) => d.effect === "deny").flatMap((d) => d.rule_ids))].sort(),
      decisions: i.decisions.map((d) => ({
        effect: d.effect,
        tool: d.tool,
        rule_ids: d.rule_ids,
        this_sha256: d.this_sha256,
        ts: d.ts,
        call_index: d.call_index ?? null,
      })),
    },
    findings: [
      {
        id: i.sessionId,
        title: `Agentic PEP receipt — ${i.sessionId}`,
        severity: "info",
        description: [
          i.task ?? `Colophon session ${i.sessionId} from PEP ${i.source}.`,
          `${i.decisions.length} decisions (${c.allow} allow, ${c.deny} deny, ${c.escalate} escalate).`,
          "This document is club interop for the Decision stream. The signed packet remains the source of custody.",
        ].join(" "),
        related_control_ids: related,
        related_resource_ids: [i.sessionId],
      },
    ],
    metadata: {
      mapping: "pep_verdict_polarity+colophon_catalog",
      pep_source: i.source,
      colophon_role: "agentic-receipt-export",
      scf_crosswalk: "deferred",
      packet_is_source_of_truth: true,
      enforcement_mode: i.record?.declaration.pep?.enforcement_mode ?? null,
      schema: FINDING_SCHEMA_VERSION,
    },
  };
  const v = validateFinding(doc);
  if (!v.ok) throw new Error(`finding export would not validate against finding.schema.json v${FINDING_SCHEMA_VERSION}: ${formatErrors(v)}`);
  return doc;
}

/** Group a Decision list by session_id (falling back to the provided session). */
export function buildFindings(i: FindingExportInput): FindingDocument[] {
  const groups = new Map<string, Decision[]>();
  for (const d of i.decisions) {
    const sid = (d.session_id && d.session_id.length > 0 ? d.session_id : i.sessionId) || i.sessionId;
    const list = groups.get(sid) ?? [];
    list.push(d);
    groups.set(sid, list);
  }
  if (groups.size === 0) return [buildFinding(i)];
  return [...groups.entries()].map(([sessionId, decisions]) => buildFinding({ ...i, sessionId, decisions }));
}
