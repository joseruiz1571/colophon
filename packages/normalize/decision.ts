/**
 * The PEP-agnostic Decision. Every adapter — the reference gate, a Claude Code
 * hook log, a CloudTrail export — emits exactly this shape, so one catalog can
 * assess any of them.
 */
import { canonicalSha256, canonicalize, hashWithout, sha256Hex } from "../schema/canonical.ts";
import { formatErrors, validateDecision } from "../schema/validate.ts";

export type Effect = "allow" | "deny" | "escalate";

/**
 * A reason names a field and the value the PEP saw there. `role` says what
 * the reason is for: `binding` (default) is the Record or policy field that
 * bounded the decision; `explanation` is the PEP's own reason text; `context`
 * is provenance (principal, request id, evaluation flags) that never bound
 * anything. The narrative renders only binding reasons as bounds.
 */
export type ReasonRole = "binding" | "explanation" | "context";
export type Reason = { field: string; value: unknown; role?: ReasonRole };

export type Decision = {
  source: "colophon-gate" | "claude-hook" | "aws-config" | "agentcore-dogwood" | string;
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

export function bindingReasons(d: Pick<Decision, "reasons">): Reason[] {
  return d.reasons.filter((r) => !r.role || r.role === "binding");
}
export function explanationReasons(d: Pick<Decision, "reasons">): Reason[] {
  return d.reasons.filter((r) => r.role === "explanation");
}
export function contextReasons(d: Pick<Decision, "reasons">): Reason[] {
  return d.reasons.filter((r) => r.role === "context");
}

const SECRET_KEY = /(token|secret|password|passwd|credential|api[_-]?key|private[_-]?key|authorization|cookie)/i;
/** A whole value that starts like a credential is committed in full. */
const SECRET_VALUE = /^(ghp_|gho_|github_pat_|sk-|xox[bpa]-|AKIA|-----BEGIN )/;
/**
 * The one credential shape both redaction and control COL-10 use. Redaction
 * commits every match inside a string; COL-10 scans the sealed view for any
 * survivor. Sharing the pattern is what keeps "redacted" and "checked" the
 * same claim.
 */
export const CREDENTIAL_PATTERN = /(ghp_[A-Za-z0-9]{10,}|gho_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|sk-[A-Za-z0-9]{10,}|xox[bpa]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const CREDENTIAL_PATTERN_G = new RegExp(CREDENTIAL_PATTERN.source, "g");
/** Keys the policy reads. Never truncated, so re-evaluation sees exactly what the gate saw. */
const POLICY_KEYS = new Set(["path", "to", "url", "scopes", "data_class", "repo", "org"]);
const MAX_STRING = 200;

function clip(k: string, v: string): string {
  if (POLICY_KEYS.has(k) || v.length <= MAX_STRING) return v;
  return v.slice(0, MAX_STRING) + ` [+${v.length - MAX_STRING} chars]`;
}

/**
 * Redact one string: a value that is a credential in full becomes one
 * commitment; a PEM block anywhere commits the whole string (the header is
 * only the start of the secret); otherwise every embedded credential-shaped
 * substring becomes its own commitment and the surrounding text survives, so
 * a Bash command keeps its shape while its token does not.
 */
export function redactString(v: string): string {
  if (SECRET_VALUE.test(v) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return commit(v);
  return v.replace(CREDENTIAL_PATTERN_G, (m) => commit(m));
}

/** Replace secret-looking values with a commitment (sha256:<hex>) so the packet can prove which value was seen without holding it; truncate long strings. Never throws. */
export function redactArgs(args: unknown): Record<string, unknown> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
    if (SECRET_KEY.test(k)) out[k] = commit(v);
    else if (typeof v === "string") out[k] = clip(k, redactString(v));
    else if (Array.isArray(v)) out[k] = v.map((x) => (typeof x === "string" ? redactString(x) : x));
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

/** Reason values are redacted at the seal, whatever adapter produced them: a reason that quotes an argument must not carry what the argument's redacted view does not. */
function redactReasons(reasons: Reason[]): Reason[] {
  return reasons.map((r) => (typeof r.value === "string" ? { ...r, value: redactString(r.value) } : r));
}

/** Chain a draft onto `prev` (null for the first decision) and seal it with this_sha256. */
export function sealDecision(draft: DecisionDraft, prev: Decision | null): Decision {
  const unsealed = { ...draft, reasons: redactReasons(draft.reasons), prev_sha256: prev ? prev.this_sha256 : null };
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
