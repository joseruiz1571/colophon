/**
 * The PEP-agnostic Decision. Every adapter — the reference gate, a Claude Code
 * hook log, a CloudTrail export — emits exactly this shape, so one catalog can
 * assess any of them.
 */
import { canonicalSha256, canonicalize, hashWithout, sha256Hex } from "../schema/canonical.ts";
import { formatErrors, validateDecision } from "../schema/validate.ts";

export type Effect = "allow" | "deny" | "escalate";

export type Reason = { field: string; value: unknown };

export type Decision = {
  source: "colophon-gate" | "claude-hook" | "aws-config" | string;
  effect: Effect;
  rule_ids: string[];
  reasons: Reason[];
  tool: string;
  args_sha256: string;
  args_redacted?: Record<string, unknown>;
  session_id?: string;
  call_index?: number;
  record_sha256?: string;
  ts: string;
  prev_sha256: string | null;
  this_sha256: string;
};

export type DecisionDraft = Omit<Decision, "this_sha256" | "prev_sha256">;

const SECRET_KEY = /(token|secret|password|passwd|credential|api[_-]?key|private[_-]?key|authorization|cookie)/i;
const SECRET_VALUE = /^(ghp_|gho_|github_pat_|sk-|xox[bpa]-|AKIA|-----BEGIN )/;
/** Keys the policy reads. Never truncated, so re-evaluation sees exactly what the gate saw. */
const POLICY_KEYS = new Set(["path", "to", "url", "scopes", "data_class", "repo", "org"]);
const MAX_STRING = 200;

function clip(k: string, v: string): string {
  if (POLICY_KEYS.has(k) || v.length <= MAX_STRING) return v;
  return v.slice(0, MAX_STRING) + ` [+${v.length - MAX_STRING} chars]`;
}

/** Replace secret-looking values with a commitment (sha256:<hex>) so the packet can prove which value was seen without holding it; truncate long strings. Never throws. */
export function redactArgs(args: unknown): Record<string, unknown> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
    if (SECRET_KEY.test(k)) out[k] = commit(v);
    else if (typeof v === "string") out[k] = SECRET_VALUE.test(v) ? commit(v) : clip(k, v);
    else if (Array.isArray(v)) out[k] = v.map((x) => (typeof x === "string" && SECRET_VALUE.test(x) ? commit(x) : x));
    else if (v !== null && typeof v === "object") out[k] = redactArgs(v);
    else out[k] = v;
  }
  return out;
}

function commit(v: unknown): string {
  return "sha256:" + sha256Hex(typeof v === "string" ? v : canonicalize(v ?? null));
}

export function argsSha256(args: unknown): string {
  return canonicalSha256(args ?? {});
}

/** Chain a draft onto `prev` (null for the first decision) and seal it with this_sha256. */
export function sealDecision(draft: DecisionDraft, prev: Decision | null): Decision {
  const unsealed = { ...draft, prev_sha256: prev ? prev.this_sha256 : null };
  const decision: Decision = { ...unsealed, this_sha256: canonicalSha256(unsealed) };
  const v = validateDecision(decision);
  if (!v.ok) throw new Error(`decision invalid: ${formatErrors(v)}`);
  return decision;
}

/** Recompute this_sha256; null when intact, otherwise the mismatch. */
export function checkSeal(decision: Decision): string | null {
  const computed = hashWithout(decision as unknown as Record<string, unknown>, "this_sha256");
  return computed === decision.this_sha256 ? null : `this_sha256 mismatch: recorded ${decision.this_sha256}, computed ${computed}`;
}
