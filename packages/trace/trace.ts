/**
 * Trace = append-only JSONL of sealed Decisions. Each line's this_sha256
 * covers the line; prev_sha256 links to the previous line. Verification
 * checks schema, seal, and linkage and names the first broken line (1-based).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { checkSeal, sealDecision, type Decision, type DecisionDraft } from "../normalize/decision.ts";
import { formatErrors, validateDecision } from "../schema/validate.ts";

/**
 * Running commitment, rewritten after every append: line count and last hash.
 * Without it, dropping the last N lines is undetectable. It is written by the
 * same process that writes the trace and covered by the bundle manifest.
 */
export type TraceHead = { trace_head_version: "0.1.0"; lines: number; last_sha256: string | null; sealed_at: string };

export function headPath(tracePath: string): string {
  return tracePath + ".head.json";
}

export class TraceWriter {
  private last: Decision | null = null;
  private count = 0;

  constructor(public readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      // Resuming an existing trace: it must verify (including its seal, if any) or we refuse to append to it.
      const v = verifyTrace(path);
      if (!v.ok) throw new Error(`refusing to append to a trace that does not verify: ${v.reason}`);
      const existing = readTrace(path);
      this.last = existing.at(-1) ?? null;
      this.count = existing.length;
    }
  }

  /** Write the terminal commitment. After this, appends are refused and truncation is detectable. */
  seal(now: Date = new Date()): TraceHead {
    const head: TraceHead = { trace_head_version: "0.1.0", lines: this.count, last_sha256: this.last?.this_sha256 ?? null, sealed_at: now.toISOString() };
    writeFileSync(headPath(this.path), JSON.stringify(head, null, 2) + "\n");
    return head;
  }

  append(draft: DecisionDraft): Decision {
    const sealed = sealDecision(draft, this.last);
    appendFileSync(this.path, JSON.stringify(sealed) + "\n");
    this.last = sealed;
    this.count += 1;
    this.seal();
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
  | { ok: true; lines: number; schema: "ok"; chain: "ok"; sealed: boolean }
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
  const hp = headPath(path);
  if (existsSync(hp)) {
    let head: TraceHead;
    try {
      head = JSON.parse(readFileSync(hp, "utf8")) as TraceHead;
    } catch {
      return { ok: false, lines: raw.length, line: raw.length, reason: `seal ${hp} is not valid JSON` };
    }
    if (head.lines !== raw.length) return { ok: false, lines: raw.length, line: raw.length, reason: `seal says ${head.lines} lines, trace has ${raw.length} (truncated or extended after sealing)` };
    const last = prev ? prev.this_sha256 : null;
    if (head.last_sha256 !== last) return { ok: false, lines: raw.length, line: raw.length, reason: `seal last_sha256 ${head.last_sha256} does not match final line ${last}` };
    return { ok: true, lines: raw.length, schema: "ok", chain: "ok", sealed: true };
  }
  return { ok: true, lines: raw.length, schema: "ok", chain: "ok", sealed: false };
}
