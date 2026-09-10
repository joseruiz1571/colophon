/**
 * Foreign PEP adapter: Claude Code PreToolUse hook events. "Their gate, your
 * packet." Consumes a fixture JSONL where each line is the hook's input event
 * plus the hook's response, and normalizes each to a Decision.
 *
 * Mapping (fail closed):
 *   permissionDecision allow → allow · deny → deny · ask → escalate ·
 *   missing/unknown → deny with CC-HOOK-NO-DECISION.
 * The rule id is the bracketed prefix of permissionDecisionReason
 * ("[CC-HOOK-SANDBOX] ...") or CC-HOOK-UNSPECIFIED when absent.
 */
import { readFileSync } from "node:fs";
import { argsSha256, redactArgs, type DecisionDraft, type Effect } from "../../normalize/decision.ts";

export const SOURCE = "claude-hook";

export type HookEvent = {
  hook_event_name: string;
  session_id: string;
  cwd?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  ts?: string;
  hook_response?: { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
};

const EFFECTS: Record<string, Effect> = { allow: "allow", deny: "deny", ask: "escalate" };

function primaryField(input: Record<string, unknown>): { field: string; value: unknown } {
  for (const k of ["file_path", "command", "path", "url", "pattern"]) {
    if (input[k] !== undefined) {
      const v = input[k];
      return { field: `tool_input.${k}`, value: typeof v === "string" && v.length > 120 ? v.slice(0, 117) + "..." : v };
    }
  }
  return { field: "tool_input", value: Object.keys(input).sort() };
}

export function normalizeHookEvent(e: HookEvent, index: number): DecisionDraft {
  const out = e.hook_response?.hookSpecificOutput;
  const raw = out?.permissionDecision;
  const effect: Effect = raw && EFFECTS[raw] ? EFFECTS[raw]! : "deny";
  const reason = out?.permissionDecisionReason ?? "";
  const m = /^\[([A-Z0-9-]+)\]\s*(.*)$/.exec(reason);
  const ruleId = !raw || !EFFECTS[raw] ? "CC-HOOK-NO-DECISION" : m ? m[1]! : "CC-HOOK-UNSPECIFIED";
  const reasonText = m ? m[2]! : reason || `hook returned ${raw ?? "no decision"}; denied`;
  const input = e.tool_input ?? {};
  return {
    source: SOURCE,
    effect,
    rule_ids: [ruleId],
    reasons: [{ field: "hook.permissionDecisionReason", value: reasonText }, primaryField(input)],
    tool: e.tool_name,
    args_sha256: argsSha256(input),
    args_redacted: redactArgs(input),
    session_id: e.session_id,
    call_index: index,
    ts: e.ts ?? new Date(0).toISOString(),
  };
}

export function normalizeClaudeHook(jsonlPath: string): { sessionId: string; task: string; drafts: DecisionDraft[] } {
  const lines = readFileSync(jsonlPath, "utf8").split("\n").filter((l) => l.trim().length > 0);
  const events = lines.map((l, i) => {
    const e = JSON.parse(l) as HookEvent;
    if (e.hook_event_name !== "PreToolUse") throw new Error(`line ${i + 1}: not a PreToolUse event (${e.hook_event_name})`);
    return e;
  });
  const sessionId = events[0]?.session_id ?? "claude-hook-empty";
  return {
    sessionId,
    task: `Claude Code session ${sessionId} in ${events[0]?.cwd ?? "?"}: ${events.length} PreToolUse events replayed from ${jsonlPath}.`,
    drafts: events.map((e, i) => normalizeHookEvent(e, i)),
  };
}
