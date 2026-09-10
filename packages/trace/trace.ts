/**
 * Trace = append-only JSONL of sealed Decisions. Each line's this_sha256
 * covers the line; prev_sha256 links to the previous line. Verification
 * checks schema, seal, and linkage and names the first broken line (1-based).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { checkSeal, sealDecision, type Decision, type DecisionDraft } from "../normalize/decision.ts";
import { formatErrors, validateDecision } from "../schema/validate.ts";

export class TraceWriter {
  private last: Decision | null = null;
  private count = 0;

  constructor(public readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const existing = readTrace(path);
      this.last = existing.at(-1) ?? null;
      this.count = existing.length;
    }
  }

  append(draft: DecisionDraft): Decision {
    const sealed = sealDecision(draft, this.last);
    appendFileSync(this.path, JSON.stringify(sealed) + "\n");
    this.last = sealed;
    this.count += 1;
    return sealed;
  }

  get length(): number {
    return this.count;
  }
}

export function readTrace(path: string): Decision[] {
  const text = readFileSync(path, "utf8");
  return text
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Decision);
}

export type TraceVerification =
  | { ok: true; lines: number; schema: "ok"; chain: "ok" }
  | { ok: false; lines: number; line: number; reason: string };

export function verifyTrace(path: string): TraceVerification {
  let raw: string[];
  try {
    raw = readFileSync(path, "utf8").split("\n").filter((l) => l.trim().length > 0);
  } catch (e) {
    return { ok: false, lines: 0, line: 0, reason: `cannot read trace: ${(e as Error).message}` };
  }
  let prev: Decision | null = null;
  for (let i = 0; i < raw.length; i++) {
    const n = i + 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw[i]!);
    } catch {
      return { ok: false, lines: raw.length, line: n, reason: `line ${n}: not valid JSON` };
    }
    const v = validateDecision(parsed);
    if (!v.ok) return { ok: false, lines: raw.length, line: n, reason: `line ${n}: schema: ${formatErrors(v)}` };
    const d = parsed as Decision;
    const seal = checkSeal(d);
    if (seal) return { ok: false, lines: raw.length, line: n, reason: `line ${n}: ${seal}` };
    const expectedPrev = prev ? prev.this_sha256 : null;
    if (d.prev_sha256 !== expectedPrev) {
      return { ok: false, lines: raw.length, line: n, reason: `line ${n}: prev_sha256 ${d.prev_sha256} does not link to line ${n - 1} (${expectedPrev})` };
    }
    prev = d;
  }
  return { ok: true, lines: raw.length, schema: "ok", chain: "ok" };
}
