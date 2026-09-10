/**
 * The only bridge between TypeScript and policy. It runs the OPA binary and
 * returns whatever the policy says, or throws. It never chooses an effect.
 */
import { spawnSync } from "node:child_process";
import { join } from "node:path";

export const POLICY_DIR = import.meta.dir;
export const GATE_POLICY = join(POLICY_DIR, "gate.rego");
export const RECORD_POLICY = join(POLICY_DIR, "record.rego");

export class OpaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpaError";
  }
}

export function opaBinary(): string {
  return process.env["COLOPHON_OPA_BIN"] ?? "opa";
}

/** Evaluate `query` against `policyPath` with `input`. Throws OpaError on any failure or undefined result. */
export function opaEval(policyPath: string, input: unknown, query: string): unknown {
  const bin = opaBinary();
  const r = spawnSync(bin, ["eval", "-f", "json", "-d", policyPath, "-I", query], {
    input: JSON.stringify(input),
    encoding: "utf8",
    timeout: 20_000,
  });
  if (r.error) throw new OpaError(`opa could not run (${bin}): ${r.error.message}`);
  if (r.status !== 0) throw new OpaError(`opa exited ${r.status}: ${(r.stderr || r.stdout || "").trim()}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    throw new OpaError(`opa returned non-JSON output: ${r.stdout.slice(0, 200)}`);
  }
  const result = (parsed as { result?: { expressions?: { value?: unknown }[] }[] }).result;
  const value = result?.[0]?.expressions?.[0]?.value;
  if (value === undefined) throw new OpaError(`opa returned no value for ${query} (undefined result)`);
  return value;
}
