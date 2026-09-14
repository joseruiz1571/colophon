/**
 * Foreign PEP adapter: Amazon Bedrock AgentCore Gateway + Dogwood. "Their
 * gate, your packet." AgentCore/Dogwood enforce; Colophon makes the decisions
 * portable evidence. This adapter does not reimplement Dogwood in Rego and
 * does not talk to AWS.
 *
 * Consumes an offline fixture of AuthorizeAction-style decision events
 * (JSONL, JSON array, or `{events: [...]}`) shaped like Dogwood CLI/blog
 * replay traces and AgentCore policy spans, and normalizes each decision
 * event to a DecisionDraft.
 *
 * Mapping (fail closed):
 *   authorization_decision / verdict ALLOW|allow → allow · DENY|deny → deny ·
 *   missing/unknown → deny with AGENTCORE-NO-DECISION.
 * History-only events (`response`, `error`) update no Decision (Dogwood replay
 * skips them). Rule ids are determining_policies, else DW-RULE-{n} from
 * determining_rules, else AGENTCORE-PERMIT / AGENTCORE-IMPLICIT-DENY.
 *
 * aws-config (CloudTrail/IAM) stays a separate adapter: infrastructure PEP
 * evidence, not AgentCore/Dogwood.
 */
import { readFileSync } from "node:fs";
import { argsSha256, redactArgs, type DecisionDraft, type Effect } from "../../normalize/decision.ts";

export const SOURCE = "agentcore-dogwood";

export type AgentcoreEvent = {
  event_kind?: string;
  history_only?: boolean;
  ts?: string;
  timestamp?: string | number;
  policy_session_id?: string;
  session_id?: string;
  tool?: string;
  action?: string;
  input?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  authorization_decision?: string;
  verdict?: string;
  decision?: string;
  authorization_reason?: string;
  determining_policies?: unknown;
  determining_rules?: unknown;
  enforcement_mode?: string;
  gateway_id?: string;
  policy_engine_arn?: string;
  policy_engine_id?: string;
  policy_set_id?: string;
  policy_set_version?: string;
  policy_set_hash?: string;
  request_id?: string;
  principal?: string;
  call_index?: number;
  attributes?: Record<string, unknown>;
};

const EFFECTS: Record<string, Effect> = { allow: "allow", deny: "deny", ALLOW: "allow", DENY: "deny" };

const HISTORY_KINDS = new Set(["response", "error"]);

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function asStringArray(v: unknown): string[] {
  if (typeof v === "string" && v.length > 0) return [v];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string" && x.length > 0);
}

function asNumberArray(v: unknown): number[] {
  if (typeof v === "number" && Number.isFinite(v)) return [v];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is number => typeof x === "number" && Number.isFinite(x));
}

function attr(e: AgentcoreEvent, key: string): unknown {
  return e.attributes?.[key];
}

function eventKind(e: AgentcoreEvent): string {
  return (str(e.event_kind) ?? str(e.attributes?.["operation.name"]) ?? "AuthorizeAction").toLowerCase();
}

function isHistoryOnly(e: AgentcoreEvent): boolean {
  if (e.history_only === true) return true;
  const kind = eventKind(e);
  if (HISTORY_KINDS.has(kind)) return true;
  const action = str(e.action) ?? "";
  return action.endsWith("::response") || action.endsWith("::error");
}

function rawDecision(e: AgentcoreEvent): string | undefined {
  return (
    str(e.authorization_decision) ??
    str(e.verdict) ??
    str(e.decision) ??
    str(attr(e, "aws.agentcore.policy.authorization_decision"))
  );
}

function toolName(e: AgentcoreEvent): string {
  return str(e.tool) ?? str(e.action) ?? str(attr(e, "aws.agentcore.policy.tool_name")) ?? "unknown-tool";
}

function sessionIdOf(e: AgentcoreEvent): string {
  return str(e.policy_session_id) ?? str(e.session_id) ?? str(attr(e, "aws.agentcore.policy.session_id")) ?? "agentcore-dogwood-empty";
}

function eventTs(e: AgentcoreEvent): string {
  if (str(e.ts)) return e.ts!;
  if (typeof e.timestamp === "string" && e.timestamp.length > 0) return e.timestamp;
  if (typeof e.timestamp === "number" && e.timestamp >= 1e12) return new Date(e.timestamp).toISOString();
  if (typeof e.timestamp === "number" && e.timestamp >= 1e9) return new Date(e.timestamp * 1000).toISOString();
  return new Date(0).toISOString();
}

function inputOf(e: AgentcoreEvent): Record<string, unknown> {
  if (e.input && typeof e.input === "object" && !Array.isArray(e.input)) return e.input;
  if (e.arguments && typeof e.arguments === "object" && !Array.isArray(e.arguments)) return e.arguments;
  return {};
}

function primaryField(input: Record<string, unknown>): { field: string; value: unknown } {
  for (const k of ["path", "file_path", "command", "to", "url", "amount", "repo", "scopes"]) {
    if (input[k] !== undefined) {
      const v = input[k];
      return { field: `input.${k}`, value: typeof v === "string" && v.length > 120 ? v.slice(0, 117) + "..." : v };
    }
  }
  return { field: "input", value: Object.keys(input).sort() };
}

function ruleIds(raw: string | undefined, effect: Effect, e: AgentcoreEvent): string[] {
  if (!raw || !EFFECTS[raw]) return ["AGENTCORE-NO-DECISION"];
  const policies = asStringArray(e.determining_policies ?? attr(e, "aws.agentcore.policy.determining_policies"));
  if (policies.length > 0) return policies;
  const rules = asNumberArray(e.determining_rules);
  if (rules.length > 0) return rules.map((n) => `DW-RULE-${n}`);
  return effect === "deny" ? ["AGENTCORE-IMPLICIT-DENY"] : ["AGENTCORE-PERMIT"];
}

export function normalizeAgentcoreEvent(e: AgentcoreEvent, index: number): DecisionDraft {
  const raw = rawDecision(e);
  const effect: Effect = raw && EFFECTS[raw] ? EFFECTS[raw]! : "deny";
  const input = inputOf(e);
  const reasonText =
    str(e.authorization_reason) ??
    str(attr(e, "aws.agentcore.policy.authorization_reason")) ??
    (raw && EFFECTS[raw] ? `Dogwood ${effect}` : `AgentCore/Dogwood returned ${raw ?? "no decision"}; denied`);
  const mode = str(e.enforcement_mode) ?? str(attr(e, "aws.agentcore.gateway.policy.mode"));
  const gateway = str(e.gateway_id) ?? str(attr(e, "aws.agentcore.policy.target_resource.id"));
  const reasons: { field: string; value: unknown }[] = [{ field: "aws.agentcore.policy.authorization_reason", value: reasonText }, primaryField(input)];
  if (mode) reasons.push({ field: "aws.agentcore.gateway.policy.mode", value: mode });
  if (gateway) reasons.push({ field: "aws.agentcore.policy.target_resource.id", value: gateway });
  if (str(e.action)) reasons.push({ field: "action", value: e.action });
  return {
    source: SOURCE,
    effect,
    rule_ids: ruleIds(raw, effect, e),
    reasons,
    tool: toolName(e),
    args_sha256: argsSha256(input),
    args_redacted: redactArgs(input),
    session_id: sessionIdOf(e),
    call_index: typeof e.call_index === "number" ? e.call_index : index,
    ts: eventTs(e),
  };
}

export type AgentcoreNormalizeResult = {
  sessionId: string;
  task: string;
  drafts: DecisionDraft[];
  evidence: { kind: string; payload: unknown }[];
};

function loadFixture(path: string): { events: AgentcoreEvent[]; task?: string; sessionId?: string } {
  const text = readFileSync(path, "utf8");
  const trimmed = text.trim();
  if (!trimmed) return { events: [] };
  if (trimmed.startsWith("[")) {
    const parsed: unknown = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error(`${path}: JSON array expected`);
    return { events: parsed as AgentcoreEvent[] };
  }
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        const o = parsed as Record<string, unknown>;
        if (Array.isArray(o["events"])) {
          return {
            events: o["events"] as AgentcoreEvent[],
            task: str(o["task"]),
            sessionId: str(o["policy_session_id"]) ?? str(o["session_id"]),
          };
        }
        if (Array.isArray(o["verdicts"]) && !o["authorization_decision"] && !o["tool"]) {
          throw new Error(
            `${path}: Dogwood replay report {verdicts} has no tool/session fields; supply AuthorizeAction decision events (JSONL or {events: [...]})`,
          );
        }
        return { events: [parsed as AgentcoreEvent] };
      }
    } catch (e) {
      if (e instanceof Error && /verdicts/.test(e.message)) throw e;
      // Multi-line JSONL of objects also starts with '{'; fall through.
    }
  }
  const events = trimmed.split("\n").filter((l) => l.trim().length > 0).map((l, i) => {
    try {
      return JSON.parse(l) as AgentcoreEvent;
    } catch {
      throw new Error(`${path}: line ${i + 1}: not valid JSON`);
    }
  });
  return { events };
}

function defaultTask(sessionId: string, drafts: DecisionDraft[], path: string): string {
  const denies = drafts.filter((d) => d.effect === "deny").length;
  const allows = drafts.filter((d) => d.effect === "allow").length;
  return [
    "Signed artifact for agent rules of engagement (AI red-team scope assurance): the declared allow/deny boundary as a reconstructible, signed packet.",
    "Coding-agent evidence of controls: which tools were declared, what AgentCore Gateway + Dogwood allowed or denied — portable for audit sampling and second-party assurance.",
    `AgentCore/Dogwood enforce; Colophon makes the decisions portable evidence. Policy session ${sessionId}: ${drafts.length} AuthorizeAction events replayed from ${path} (${allows} allow, ${denies} deny).`,
    "Live CloudWatch/EventBridge ingest is not in this packet (Phase 4 deferred).",
  ].join(" ");
}

export function normalizeAgentcoreDogwood(jsonlPath: string): AgentcoreNormalizeResult {
  const loaded = loadFixture(jsonlPath);
  const decisionEvents = loaded.events.filter((e) => !isHistoryOnly(e));
  const drafts = decisionEvents.map((e, i) => normalizeAgentcoreEvent(e, i));
  const sessionId = loaded.sessionId ?? drafts[0]?.session_id ?? (decisionEvents[0] ? sessionIdOf(decisionEvents[0]) : "agentcore-dogwood-empty");
  const first = decisionEvents[0];
  const evidence: { kind: string; payload: unknown }[] = [];
  if (first) {
    evidence.push({
      kind: "agentcore-pep-binding",
      payload: {
        source: SOURCE,
        policy_session_id: sessionId,
        enforcement_mode: str(first.enforcement_mode) ?? str(attr(first, "aws.agentcore.gateway.policy.mode")) ?? null,
        gateway_id: str(first.gateway_id) ?? str(attr(first, "aws.agentcore.policy.target_resource.id")) ?? null,
        policy_engine_arn: str(first.policy_engine_arn) ?? str(attr(first, "aws.agentcore.gateway.policy.arn")) ?? null,
        policy_engine_id: str(first.policy_engine_id) ?? null,
        policy_set_id: str(first.policy_set_id) ?? null,
        policy_set_version: str(first.policy_set_version) ?? null,
        policy_set_hash: str(first.policy_set_hash) ?? null,
        note: "Fixture replay of a foreign PEP. Colophon did not evaluate Dogwood; it normalized the recorded allow/deny decisions.",
      },
    });
  }
  return {
    sessionId,
    task: loaded.task ?? defaultTask(sessionId, drafts, jsonlPath),
    drafts,
    evidence,
  };
}
