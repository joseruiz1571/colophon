/**
 * Foreign PEP adapter: Amazon Bedrock AgentCore Gateway + Dogwood. "Their
 * gate, your packet." AgentCore/Dogwood enforce; Colophon makes the decisions
 * portable evidence. This adapter does not reimplement Dogwood in Rego and
 * does not talk to AWS.
 *
 * Two offline inputs (no SDK, no credentials, no network):
 *
 * 1. Dogwood CLI / AuthorizeAction fixture (JSONL, JSON array, or
 *    `{events: [...]}`) shaped like replay traces and AgentCore policy spans.
 *    Mapping (fail closed): authorization_decision / verdict ALLOW|allow →
 *    allow · DENY|deny → deny · missing/unknown → deny with AGENTCORE-NO-DECISION.
 *    History-only events (`response`, `error`) update no Decision. Rule ids are
 *    determining_policies, else DW-RULE-{n} from determining_rules, else
 *    AGENTCORE-PERMIT / AGENTCORE-IMPLICIT-DENY.
 *
 * 2. AgentCore Gateway APPLICATION_LOGS JSONL. Session id is NOT in the log
 *    body — it must come from a sidecar `<stem>.meta.json` or `--session`.
 *    Tool name + arguments are joined from `Started processing request` onto
 *    `Policy evaluation completed` (ALLOW) / `Policy evaluation denied request`
 *    (DENY) on `request_id`. determiningPolicies become rule_ids; empty →
 *    AGENTCORE-DEFAULT-DENY.
 *
 * aws-config (CloudTrail/IAM) stays a separate adapter: infrastructure PEP
 * evidence, not AgentCore/Dogwood.
 */
import { existsSync, readFileSync } from "node:fs";
import { relative } from "node:path";
import { argsSha256, redactArgs, redactString, type DecisionDraft, type Effect, type Reason } from "../../normalize/decision.ts";

/** A packet is portable evidence: paths inside it are relative to the directory it was built from, never the build machine's absolute path. */
function portable(p: string): string {
  const r = relative(process.cwd(), p);
  return r.length > 0 && !r.startsWith("..") ? r : p;
}

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

export type AgentcoreCaptureMeta = {
  session_id?: string;
  region?: string;
  account_last4?: string;
  gateway_id?: string;
  gateway_url?: string;
  policy_engine?: string;
  policy_engine_arn?: string;
  mode?: string;
  auth?: string;
  window_ms?: unknown;
  policies_active?: unknown;
  target?: string;
  lambda?: string;
  log_group?: string;
  note?: string;
  [k: string]: unknown;
};

export type AgentcoreNormalizeOptions = {
  sessionId?: string;
  metaPath?: string;
};

const EFFECTS: Record<string, Effect> = { allow: "allow", deny: "deny", ALLOW: "allow", DENY: "deny" };

const HISTORY_KINDS = new Set(["response", "error"]);

const STARTED = "Started processing request";
const EVAL_ALLOW = "Policy evaluation completed";
const EVAL_DENY = "Policy evaluation denied request";

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

function asObj(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
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
  for (const k of ["path", "file_path", "command", "to", "url", "amount", "repo", "scopes", "action"]) {
    if (input[k] !== undefined) {
      const v = input[k];
      // Redact before truncating: a cut token would otherwise escape the pattern.
      const s = typeof v === "string" ? redactString(v) : v;
      return { field: `input.${k}`, value: typeof s === "string" && s.length > 120 ? s.slice(0, 117) + "..." : s };
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
  // The PEP's reason text explains; the primary argument is the bound value; the mode is context.
  const reasons: Reason[] = [{ field: "aws.agentcore.policy.authorization_reason", value: reasonText, role: "explanation" }, primaryField(input)];
  if (mode === "LOG_ONLY") reasons.push({ field: "aws.agentcore.gateway.policy.mode", value: mode, role: "context" });
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

function loadFixture(path: string): { events: unknown[]; task?: string; sessionId?: string } {
  const text = readFileSync(path, "utf8");
  const trimmed = text.trim();
  if (!trimmed) return { events: [] };
  if (trimmed.startsWith("[")) {
    const parsed: unknown = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error(`${path}: JSON array expected`);
    return { events: parsed };
  }
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        const o = parsed as Record<string, unknown>;
        if (Array.isArray(o["events"])) {
          return {
            events: o["events"],
            task: str(o["task"]),
            sessionId: str(o["policy_session_id"]) ?? str(o["session_id"]),
          };
        }
        if (Array.isArray(o["verdicts"]) && !o["authorization_decision"] && !o["tool"]) {
          throw new Error(
            `${path}: Dogwood replay report {verdicts} has no tool/session fields; supply AuthorizeAction decision events (JSONL or {events: [...]})`,
          );
        }
        return { events: [parsed] };
      }
    } catch (e) {
      if (e instanceof Error && /verdicts/.test(e.message)) throw e;
      // Multi-line JSONL of objects also starts with '{'; fall through.
    }
  }
  const events = trimmed.split("\n").filter((l) => l.trim().length > 0).map((l, i) => {
    try {
      return JSON.parse(l) as unknown;
    } catch {
      throw new Error(`${path}: line ${i + 1}: not valid JSON`);
    }
  });
  return { events };
}

function logOf(row: unknown): string | undefined {
  return str(asObj(row)?.["log"]);
}

function isApplicationLogs(rows: unknown[]): boolean {
  return rows.some((r) => {
    const log = logOf(r);
    return log === STARTED || log === EVAL_ALLOW || log === EVAL_DENY;
  });
}

/**
 * Parse AWS Java-style `{k=v, nested={k2=v2}}` maps from Gateway APPLICATION_LOGS
 * requestBody. This is not JSON.
 */
export function parseAwsStyleMap(raw: string): Record<string, unknown> {
  const s = raw.trim();
  const i = s.indexOf("{");
  const j = s.lastIndexOf("}");
  if (i < 0 || j <= i) return {};
  const inner = s.slice(i + 1, j).trim();
  if (!inner) return {};
  const pairs: string[] = [];
  let depth = 0;
  let start = 0;
  for (let p = 0; p < inner.length; p++) {
    const c = inner[p];
    if (c === "{") depth++;
    else if (c === "}") depth--;
    else if (c === "," && depth === 0) {
      pairs.push(inner.slice(start, p));
      start = p + 1;
    }
  }
  pairs.push(inner.slice(start));
  const out: Record<string, unknown> = {};
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).trim();
    const val = pair.slice(eq + 1).trim();
    if (!key) continue;
    out[key] = val.startsWith("{") && val.endsWith("}") ? parseAwsStyleMap(val) : val;
  }
  return out;
}

function toolAndArgsFromRequestBody(requestBody: unknown): { tool: string; args: Record<string, unknown> } {
  let parsed: Record<string, unknown> = {};
  if (typeof requestBody === "string") parsed = parseAwsStyleMap(requestBody);
  else {
    const o = asObj(requestBody);
    if (o) parsed = o;
  }
  const params = asObj(parsed["params"]) ?? {};
  const tool = str(params["name"]) ?? "unknown-tool";
  const args = asObj(params["arguments"]) ?? {};
  return { tool, args };
}

function msToIso(ts: unknown): string {
  if (typeof ts === "number" && ts >= 1e12) return new Date(ts).toISOString();
  if (typeof ts === "number" && ts >= 1e9) return new Date(ts * 1000).toISOString();
  if (typeof ts === "string" && ts.length > 0) {
    const n = Number(ts);
    if (Number.isFinite(n) && n >= 1e12) return new Date(n).toISOString();
    return ts;
  }
  return new Date(0).toISOString();
}

function defaultSidecarPath(jsonlPath: string): string {
  return jsonlPath.replace(/\.jsonl$/i, "").replace(/\.json$/i, "") + ".meta.json";
}

export function loadCaptureMeta(path: string): AgentcoreCaptureMeta {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  const o = asObj(parsed);
  if (!o) throw new Error(`${path}: capture metadata must be a JSON object`);
  return o as AgentcoreCaptureMeta;
}

function resolveCaptureMeta(jsonlPath: string, opts: AgentcoreNormalizeOptions): { meta: AgentcoreCaptureMeta | null; path: string | null } {
  const explicit = str(opts.metaPath);
  const candidate = explicit ?? (existsSync(defaultSidecarPath(jsonlPath)) ? defaultSidecarPath(jsonlPath) : null);
  if (!candidate) return { meta: null, path: null };
  if (!existsSync(candidate)) throw new Error(`${candidate}: capture metadata file not found`);
  return { meta: loadCaptureMeta(candidate), path: candidate };
}

function applicationLogsTask(sessionId: string, drafts: DecisionDraft[], path: string, meta: AgentcoreCaptureMeta | null): string {
  const denies = drafts.filter((d) => d.effect === "deny").length;
  const allows = drafts.filter((d) => d.effect === "allow").length;
  const mode = str(meta?.mode) ?? "ENFORCE";
  const auth = str(meta?.auth) ?? "AWS_IAM";
  return [
    "Signed artifact for agent rules of engagement (AI red-team scope assurance): the declared allow/deny boundary as a reconstructible, signed packet.",
    "Coding-agent evidence of controls: which tools were declared, what AgentCore Gateway + Dogwood allowed or denied — portable for audit sampling and second-party assurance.",
    `AgentCore/Dogwood enforce; Colophon makes the decisions portable evidence. APPLICATION_LOGS capture for policy session ${sessionId}: ${drafts.length} Gateway policy evaluations joined on request_id from ${portable(path)} (${allows} allow, ${denies} deny). Session id is capture metadata, not a field in the log body. ${mode} + ${auth}.`,
    "Colophon did not call CloudWatch or EventBridge; this packet is an offline ingest of captured Gateway logs.",
  ].join(" ");
}

function authorizeActionTask(sessionId: string, drafts: DecisionDraft[], path: string): string {
  const denies = drafts.filter((d) => d.effect === "deny").length;
  const allows = drafts.filter((d) => d.effect === "allow").length;
  return [
    "Signed artifact for agent rules of engagement (AI red-team scope assurance): the declared allow/deny boundary as a reconstructible, signed packet.",
    "Coding-agent evidence of controls: which tools were declared, what AgentCore Gateway + Dogwood allowed or denied — portable for audit sampling and second-party assurance.",
    `AgentCore/Dogwood enforce; Colophon makes the decisions portable evidence. Policy session ${sessionId}: ${drafts.length} AuthorizeAction events replayed from ${portable(path)} (${allows} allow, ${denies} deny).`,
    "AuthorizeAction fixture replay (Dogwood CLI / span export). APPLICATION_LOGS Gateway ingest is a separate path; neither calls CloudWatch.",
  ].join(" ");
}

function normalizeApplicationLogs(
  jsonlPath: string,
  rows: unknown[],
  opts: AgentcoreNormalizeOptions,
): AgentcoreNormalizeResult {
  const { meta, path: metaPath } = resolveCaptureMeta(jsonlPath, opts);
  const sessionId = str(opts.sessionId) ?? str(meta?.session_id);
  if (!sessionId) {
    throw new Error(
      `${jsonlPath}: APPLICATION_LOGS bodies do not carry session_id; pass --session <id> or a sidecar ${defaultSidecarPath(jsonlPath)}`,
    );
  }

  type Started = { tool: string; args: Record<string, unknown> };
  const started = new Map<string, Started>();
  const drafts: DecisionDraft[] = [];

  for (const row of rows) {
    const o = asObj(row);
    if (!o) continue;
    const log = str(o["log"]);
    const requestId = str(o["request_id"]);
    if (log === STARTED) {
      if (!requestId) continue;
      started.set(requestId, toolAndArgsFromRequestBody(o["requestBody"]));
      continue;
    }
    if (log !== EVAL_ALLOW && log !== EVAL_DENY) continue;
    const policy = asObj(o["policy"]) ?? {};
    const raw = str(policy["decision"]);
    const effect: Effect = raw && EFFECTS[raw] ? EFFECTS[raw]! : "deny";
    const joined = requestId ? started.get(requestId) : undefined;
    const tool = joined?.tool ?? "unknown-tool";
    const input = joined?.args ?? {};
    const policies = asStringArray(policy["determiningPolicies"]);
    const rule_ids = !raw || !EFFECTS[raw] ? ["AGENTCORE-NO-DECISION"] : policies.length > 0 ? policies : ["AGENTCORE-DEFAULT-DENY"];
    const principal = asObj(policy["principal"]);
    const reasonText = str(policy["reason"]) ?? log ?? (raw && EFFECTS[raw] ? `AgentCore ${effect}` : `AgentCore/Dogwood returned ${raw ?? "no decision"}; denied`);
    // Binding first (what the policy keyed on), then the Gateway's own words,
    // then provenance. Only the binding reason is a bound; the narrative
    // renders the rest as what they are.
    const reasons: Reason[] = [primaryField(input)];
    reasons.push({ field: "aws.agentcore.policy.authorization_reason", value: reasonText, role: "explanation" });
    if (str(principal?.["entityId"])) reasons.push({ field: "aws.agentcore.policy.principal.entityId", value: principal!["entityId"], role: "context" });
    if (requestId) reasons.push({ field: "aws.agentcore.policy.request_id", value: requestId, role: "context" });
    if (typeof policy["temporal_evaluation_invoked"] === "boolean") {
      reasons.push({ field: "aws.agentcore.policy.temporal_evaluation_invoked", value: policy["temporal_evaluation_invoked"], role: "context" });
    }
    const mode = str(meta?.mode);
    if (mode === "LOG_ONLY") reasons.push({ field: "aws.agentcore.gateway.policy.mode", value: mode, role: "context" });
    drafts.push({
      source: SOURCE,
      effect,
      rule_ids,
      reasons,
      tool,
      args_sha256: argsSha256(input),
      args_redacted: redactArgs(input),
      session_id: sessionId,
      call_index: drafts.length,
      ts: msToIso(o["ts"]),
    });
  }

  const firstPolicy = rows.map((r) => asObj(asObj(r)?.["policy"])).find((p) => p);
  const evidence: { kind: string; payload: unknown }[] = [];
  evidence.push({
    kind: "agentcore-pep-binding",
    payload: {
      source: SOURCE,
      ingest: "application-logs",
      policy_session_id: sessionId,
      enforcement_mode: str(meta?.mode) ?? "ENFORCE",
      gateway_id: str(meta?.gateway_id) ?? null,
      gateway_url: str(meta?.gateway_url) ?? null,
      policy_engine_id: str(meta?.policy_engine) ?? null,
      policy_engine_arn: str(firstPolicy?.["policyEngineArn"]) ?? str(meta?.policy_engine_arn) ?? null,
      auth: str(meta?.auth) ?? null,
      region: str(meta?.region) ?? null,
      account_last4: str(meta?.account_last4) ?? null,
      window_ms: meta?.window_ms ?? null,
      policies_active: meta?.policies_active ?? null,
      target: str(meta?.target) ?? null,
      lambda: str(meta?.lambda) ?? null,
      note: "APPLICATION_LOGS capture of a foreign PEP. Session id came from sidecar/CLI metadata, not the log body. Colophon did not evaluate Dogwood; it normalized the recorded allow/deny decisions.",
    },
  });
  if (meta) {
    evidence.push({
      kind: "agentcore-capture-metadata",
      payload: { ...meta, sidecar: metaPath ? portable(metaPath) : null, note: meta.note ?? "Session id is capture metadata; AgentCore APPLICATION_LOGS bodies do not carry it." },
    });
  }
  return {
    sessionId,
    task: applicationLogsTask(sessionId, drafts, jsonlPath, meta),
    drafts,
    evidence,
  };
}

export function normalizeAgentcoreDogwood(jsonlPath: string, opts: AgentcoreNormalizeOptions = {}): AgentcoreNormalizeResult {
  const loaded = loadFixture(jsonlPath);
  if (isApplicationLogs(loaded.events)) return normalizeApplicationLogs(jsonlPath, loaded.events, opts);

  const decisionEvents = (loaded.events as AgentcoreEvent[]).filter((e) => !isHistoryOnly(e));
  const drafts = decisionEvents.map((e, i) => {
    const d = normalizeAgentcoreEvent(e, i);
    const override = str(opts.sessionId);
    return override ? { ...d, session_id: override } : d;
  });
  const sessionId =
    str(opts.sessionId) ?? loaded.sessionId ?? drafts[0]?.session_id ?? (decisionEvents[0] ? sessionIdOf(decisionEvents[0]) : "agentcore-dogwood-empty");
  const first = decisionEvents[0];
  const evidence: { kind: string; payload: unknown }[] = [];
  if (first) {
    evidence.push({
      kind: "agentcore-pep-binding",
      payload: {
        source: SOURCE,
        ingest: "authorize-action",
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
    task: loaded.task ?? authorizeActionTask(sessionId, drafts, jsonlPath),
    drafts,
    evidence,
  };
}
