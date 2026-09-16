/**
 * Colophon as a Claude Code PreToolUse hook: the reference verdict path
 * (gate.rego through OPA) over a second transport. One process per tool call:
 * read the event on stdin, bind the Record (hash, signature, lint), decide,
 * append one chained Decision to <trace-dir>/<session_id>.jsonl, print the
 * hook JSON. `seal` turns that trace into a packet at session end.
 *
 * The hook never rewrites tool input (no updatedInput): custody, not editing.
 * Fail closed: a malformed event, an unverifiable Record, or an OPA failure
 * is a deny, appended to the trace whenever a session id is known.
 *
 * Contract (Claude Code hooks reference, read 2026-09-16): stdin JSON carries
 * session_id, cwd, hook_event_name, tool_name, tool_input; stdout JSON is
 * {hookSpecificOutput: {hookEventName, permissionDecision: allow|deny|ask,
 * permissionDecisionReason}} with exit 0; the deny reason is shown to Claude.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { buildPacket, type PacketOutput, type Signer } from "../cli/packet.ts";
import { decide, failClosedDeny, selfTest, type Verdict } from "../gate/eval.ts";
import { bindRecord, recordSignaturePath } from "../gate/server.ts";
import { argsSha256, bindingReasons, redactArgs, type Effect, type Reason } from "../normalize/decision.ts";
import { canonicalSha256 } from "../schema/canonical.ts";
import type { ColophonRecord, Declaration } from "../schema/record.ts";
import { readTrace, TraceWriter } from "../trace/trace.ts";


export const SOURCE = "colophon-hook";

export type HookEvent = {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
  permission_mode?: string;
};

export type PermissionDecision = "allow" | "deny" | "ask";

export type HookOutput = {
  hookSpecificOutput: { hookEventName: "PreToolUse"; permissionDecision: PermissionDecision; permissionDecisionReason: string };
};

/**
 * Claude Code tool name → declared tool name. A naming contract like
 * pep.tool_name_prefix (D29): it maps names, it never decides. Unknown names
 * are lower-cased into the Declaration's grammar and left to the gate, which
 * refuses anything not declared.
 */
export const TOOL_MAP: Record<string, string> = {
  Read: "fs.read",
  Glob: "fs.read",
  Grep: "fs.read",
  Write: "fs.write",
  Edit: "fs.write",
  MultiEdit: "fs.write",
  NotebookEdit: "fs.write",
  Bash: "shell.exec",
  WebFetch: "net.fetch",
  WebSearch: "net.search",
};

function segment(s: string): string {
  const t = s.toLowerCase().replace(/[^a-z0-9_]/g, "_").replace(/^[^a-z]+/, "");
  return t.length > 0 ? t : "unnamed";
}

export function declaredToolName(claudeTool: string): string {
  const mapped = TOOL_MAP[claudeTool];
  if (mapped) return mapped;
  if (claudeTool.startsWith("mcp__")) return claudeTool.split("__").filter((p) => p.length > 0).map(segment).join(".");
  return segment(claudeTool);
}

/**
 * A path inside `cwd` becomes cwd-relative (`src/index.ts`) so a Declaration's
 * sandbox can be written once and signed for any machine; a path outside stays
 * absolute, which no relative write_paths prefix admits. Resolved first, so
 * `src/../../etc` lands outside.
 */
export function portablePath(cwd: string | undefined, p: string): string {
  if (!cwd) return p;
  const abs = resolve(cwd, p);
  const rel = relative(cwd, abs);
  if (rel === "") return ".";
  if (rel.startsWith("..") || isAbsolute(rel)) return abs;
  return rel;
}

export type MappedCall = { name: string; arguments: Record<string, unknown>; context: Reason[] };

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

const FS_TOOLS = new Set(["Read", "Glob", "Grep", "Write", "Edit", "MultiEdit", "NotebookEdit"]);

/** Project the Claude Code call onto the arguments the gate's rules read; keep full-input fidelity as a hash in context. */
export function mapCall(e: HookEvent, defaults: Declaration["defaults"]): MappedCall {
  const tool = e.tool_name ?? "unknown";
  const input = e.tool_input && typeof e.tool_input === "object" && !Array.isArray(e.tool_input) ? e.tool_input : {};
  const name = declaredToolName(tool);
  let args: Record<string, unknown>;
  if (FS_TOOLS.has(tool)) {
    const raw = str(input["file_path"]) ?? str(input["notebook_path"]) ?? str(input["path"]) ?? e.cwd ?? ".";
    args = { path: portablePath(e.cwd, raw) };
    if (str(input["pattern"])) args["pattern"] = input["pattern"];
  } else if (tool === "Bash") args = { command: input["command"] ?? "" };
  else if (tool === "WebFetch") args = { url: input["url"] ?? "" };
  else if (tool === "WebSearch") args = { query: input["query"] ?? "" };
  else args = { ...input };

  const context: Reason[] = [
    { field: "claude.tool_name", value: tool, role: "context" },
    { field: "claude.tool_input_sha256", value: canonicalSha256(input), role: "context" },
  ];
  if (e.cwd) context.push({ field: "claude.cwd", value: e.cwd, role: "context" });
  if (e.tool_use_id) context.push({ field: "claude.tool_use_id", value: e.tool_use_id, role: "context" });
  if (args["data_class"] === undefined && defaults?.data_class) {
    // The operator's blanket label, not the agent's: recorded as such (D4, D32).
    args["data_class"] = defaults.data_class;
    context.push({ field: "defaults.data_class", value: defaults.data_class, role: "context" });
  }
  return { name, arguments: args, context };
}

const PERMISSION: Record<Effect, PermissionDecision> = { allow: "allow", deny: "deny", escalate: "ask" };

/** `[RULE-ID] field: value; …` so the existing claude-hook adapter can replay a hook log and recover the same rule id. */
export function reasonText(v: Verdict): string {
  const [first, ...rest] = v.rule_ids;
  const bounds = bindingReasons(v).map((r) => `${r.field}: ${JSON.stringify(r.value)}`).join("; ");
  return `[${first ?? "COL-GATE-DEFAULT-DENY"}] ${bounds}${rest.length ? ` (also ${rest.join(", ")})` : ""}`;
}

export function toOutput(v: Verdict): HookOutput {
  return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: PERMISSION[v.effect], permissionDecisionReason: reasonText(v) } };
}

export function safeSessionId(id: string): string {
  return id.replace(/[^A-Za-z0-9._-]/g, "_");
}

export function tracePathFor(traceDir: string, sessionId: string): string {
  return join(traceDir, `${safeSessionId(sessionId)}.jsonl`);
}

export function selftestPathFor(traceDir: string, sessionId: string): string {
  return join(traceDir, `${safeSessionId(sessionId)}.selftest.json`);
}

export type HookRunOptions = { recordPath: string; pubkeyPath?: string; traceDir: string; policyPath?: string; now?: () => Date };

export type HookRunResult = { output: HookOutput; verdict: Verdict; sessionId: string | null; tracePath: string | null; tool: string };

/** One PreToolUse event → one decision. Never throws; every failure is a deny. */
export function runHook(raw: string, o: HookRunOptions): HookRunResult {
  const now = o.now ?? (() => new Date());
  let event: HookEvent | null = null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) event = parsed as HookEvent;
  } catch {
    event = null;
  }
  const sessionId = str(event?.session_id) ?? null;
  const tool = str(event?.tool_name) ?? "unknown";
  const tracePath = sessionId ? tracePathFor(o.traceDir, sessionId) : null;

  try {
    if (!event || event.hook_event_name !== "PreToolUse" || !sessionId || !str(event.tool_name)) {
      throw new Error("malformed PreToolUse event: need hook_event_name=PreToolUse, session_id, tool_name");
    }
    const record: ColophonRecord = bindRecord(o.recordPath, o.pubkeyPath);
    mkdirSync(o.traceDir, { recursive: true });
    const trace = new TraceWriter(tracePath!);
    if (trace.length === 0) {
      // First call of the session: prove fail-closed on this machine, now (COL-02 evidence).
      const st = selfTest(record);
      if (!st.ok) throw new Error(`fail-closed self-test failed: ${JSON.stringify(st)}`);
      writeFileSync(selftestPathFor(o.traceDir, sessionId), JSON.stringify({ record_sha256: record.canonical_sha256, ...st }, null, 2) + "\n");
    }
    const call = mapCall(event, record.declaration.defaults);
    const context = { session_id: sessionId, call_index: trace.length };
    const verdict = decide(record, { name: call.name, arguments: call.arguments }, context, o.policyPath, true);
    trace.append({
      source: SOURCE,
      effect: verdict.effect,
      rule_ids: verdict.rule_ids,
      reasons: [...verdict.reasons, ...call.context],
      tool: call.name,
      args_sha256: argsSha256(call.arguments),
      args_redacted: redactArgs(call.arguments),
      session_id: sessionId,
      call_index: context.call_index,
      record_sha256: record.canonical_sha256,
      ts: now().toISOString(),
    });
    return { output: toOutput(verdict), verdict, sessionId, tracePath, tool: call.name };
  } catch (e) {
    const verdict = failClosedDeny((e as Error).message ?? String(e));
    const name = declaredToolName(tool);
    if (sessionId && tracePath) {
      try {
        mkdirSync(o.traceDir, { recursive: true });
        const trace = new TraceWriter(tracePath);
        const input = event?.tool_input ?? {};
        trace.append({
          source: SOURCE,
          effect: verdict.effect,
          rule_ids: verdict.rule_ids,
          reasons: [...verdict.reasons, { field: "claude.tool_name", value: tool, role: "context" }],
          tool: name,
          args_sha256: argsSha256(input),
          args_redacted: redactArgs(input),
          session_id: sessionId,
          call_index: trace.length,
          ts: now().toISOString(),
        });
      } catch {
        // The trace itself is unusable; the deny still goes out.
      }
    }
    return { output: toOutput(verdict), verdict, sessionId, tracePath, tool: name };
  }
}

export type SealOptions = { sessionId: string; traceDir: string; recordPath: string; pubkeyPath?: string; outRoot: string; signer: Signer; name?: string };

/** Session end: the hook's trace → assessed, signed, verified packet. Throws on any failure; prints nothing. */
export function sealSession(o: SealOptions): PacketOutput {
  const tracePath = tracePathFor(o.traceDir, o.sessionId);
  if (!existsSync(tracePath)) throw new Error(`no trace for session ${o.sessionId} under ${o.traceDir} (${basename(tracePath)} missing)`);
  const record = bindRecord(o.recordPath, o.pubkeyPath);
  const decisions = readTrace(tracePath);
  const counts = { allow: 0, deny: 0, escalate: 0 };
  for (const d of decisions) counts[d.effect]++;
  const task = [
    `Claude Code session ${o.sessionId}: ${decisions.length} PreToolUse decisions by the Colophon hook (the PEP) against Record ${record.declaration.name}`,
    `(${counts.allow} allowed, ${counts.deny} refused, ${counts.escalate} handed to the human as ask).`,
    "Verdicts came from gate.rego through OPA on every call; the hook rewrote no tool input. An ask records that the human was asked, not what the human chose.",
  ].join(" ");
  const selftest = selftestPathFor(o.traceDir, o.sessionId);
  return buildPacket({
    name: o.name ?? safeSessionId(o.sessionId),
    source: SOURCE,
    sessionId: o.sessionId,
    task,
    outRoot: o.outRoot,
    tracePath,
    record: { path: o.recordPath, sigPath: recordSignaturePath(o.recordPath), record },
    selftestPath: existsSync(selftest) ? selftest : undefined,
    signer: o.signer,
  });
}

/** The `.claude/settings.json` fragment a human pastes. Machine paths are absolute on purpose: this is config, not a packet. */
export function settingsSnippet(o: { cli: string; recordPath: string; pubkeyPath: string; traceDir: string }): Record<string, unknown> {
  const command = ["bun", resolve(o.cli), "hook", "--record", resolve(o.recordPath), "--pubkey", resolve(o.pubkeyPath), "--trace-dir", resolve(o.traceDir)].join(" ");
  return { hooks: { PreToolUse: [{ matcher: "", hooks: [{ type: "command", command, timeout: 30 }] }] } };
}
