/**
 * Bridge between a tool call and the Rego verdict. Builds the policy input,
 * asks OPA, and validates the shape of what comes back. If anything goes
 * wrong the result is a deny with COL-GATE-OPA-ERROR: this is the one place
 * TypeScript names an effect, and it only ever names deny.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GATE_POLICY, OpaError, opaEval } from "../policy/opa.ts";
import { sha256Hex } from "../schema/canonical.ts";
import type { ColophonRecord } from "../schema/record.ts";
import type { Effect, Reason } from "../normalize/decision.ts";

export type Verdict = { effect: Effect; rule_ids: string[]; reasons: Reason[] };
export type Call = { name: string; arguments: Record<string, unknown> };
/** `as_of` (RFC 3339) makes a re-evaluation of a recorded Decision ask the review-date question at that Decision's time; a live call omits it. */
export type CallContext = { session_id: string; call_index: number; as_of?: string };

const EFFECTS = new Set<string>(["allow", "deny", "escalate"]);

function shapeOk(v: unknown): v is Verdict {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o["effect"] === "string" && EFFECTS.has(o["effect"]) &&
    Array.isArray(o["rule_ids"]) && o["rule_ids"].length > 0 && o["rule_ids"].every((r) => typeof r === "string" && r.length > 0) &&
    Array.isArray(o["reasons"]) && o["reasons"].length > 0 &&
    o["reasons"].every((r) => r && typeof r === "object" && typeof (r as Reason).field === "string" && (r as Reason).field.length > 0)
  );
}

export function gatePolicyPath(): string {
  return process.env["COLOPHON_GATE_POLICY"] ?? GATE_POLICY;
}

/**
 * SHA-256 of the policy file's bytes, recorded on every Decision as
 * policy_sha256 so the packet can stage the file and a verifier can check that
 * the verdicts came from exactly that text. Undefined when the file cannot be
 * read: that is the OPA-error path, whose deny already names the missing
 * policy in its reasons, and a hash of nothing would be a claim about nothing.
 */
export function policySha256(policyPath: string = gatePolicyPath()): string | undefined {
  try {
    return sha256Hex(readFileSync(policyPath));
  } catch {
    return undefined;
  }
}

/** The one effect TypeScript ever names: the fail-closed deny when the policy engine could not decide (D6). Shared by the gate and the hook. */
export function failClosedDeny(message: string): Verdict {
  return { effect: "deny", rule_ids: ["COL-GATE-OPA-ERROR"], reasons: [{ field: "policy", value: message.slice(0, 300) }] };
}

export function decide(record: ColophonRecord | null, call: Call, context: CallContext, policyPath: string = gatePolicyPath(), quiet = false): Verdict {
  try {
    const value = opaEval(policyPath, { record, call, context }, "data.colophon.gate.decision");
    if (!shapeOk(value)) throw new OpaError(`policy returned a malformed verdict: ${JSON.stringify(value).slice(0, 200)}`);
    return value;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (!quiet) process.stderr.write(`[gate] policy evaluation failed, denying: ${message.split("\n")[0]}\n`);
    return failClosedDeny(message);
  }
}

let snapshotDir: string | undefined;

/** A private copy of exactly the policy bytes that were hashed, named by their hash, so OPA evaluates what was hashed and nothing else (S64). */
function snapshotPolicy(bytes: Buffer, sha: string): string {
  if (!snapshotDir) {
    snapshotDir = mkdtempSync(join(tmpdir(), "colophon-policy-"));
    const dir = snapshotDir;
    process.on("exit", () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort; the directory is private and holds only policy text
      }
    });
  }
  const path = join(snapshotDir, `${sha}.rego`);
  if (!existsSync(path)) writeFileSync(path, bytes, { mode: 0o600 });
  return path;
}

export type Decided = { verdict: Verdict; policy_sha256: string | undefined };

/**
 * Decide and name the policy in one read. The policy file is read once; the
 * hash is of those bytes and OPA evaluates a copy of those bytes, so a file
 * edited while the enforcement point runs cannot credit a verdict to a hash of
 * different text. An unreadable policy takes the fail-closed path with no hash.
 */
export function decideBound(record: ColophonRecord | null, call: Call, context: CallContext, policyPath: string = gatePolicyPath(), quiet = false): Decided {
  let bytes: Buffer;
  try {
    bytes = readFileSync(policyPath);
  } catch {
    return { verdict: decide(record, call, context, policyPath, quiet), policy_sha256: undefined };
  }
  const sha = sha256Hex(bytes);
  return { verdict: decide(record, call, context, snapshotPolicy(bytes, sha), quiet), policy_sha256: sha };
}

/**
 * Startup self-test: prove fail-closed behaviour on this machine, right now,
 * and return it as evidence. Two probes: an undeclared tool, and a policy
 * path that does not exist (OPA error path).
 */
export function selfTest(record: ColophonRecord): { unknown_tool: Verdict; opa_error: Verdict; ok: boolean } {
  const ctx = { session_id: "self-test", call_index: -1 };
  const unknown = decide(record, { name: "colophon.selftest.undeclared_tool", arguments: {} }, ctx);
  const errored = decide(record, { name: record.declaration.tools[0]!.name, arguments: {} }, ctx, "/nonexistent/colophon-selftest.rego", true);
  return {
    unknown_tool: unknown,
    opa_error: errored,
    ok: unknown.effect === "deny" && errored.effect === "deny" && errored.rule_ids.includes("COL-GATE-OPA-ERROR"),
  };
}
