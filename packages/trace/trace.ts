/**
 * Trace = append-only JSONL of sealed Decisions. Each line's this_sha256
 * covers the line; prev_sha256 links to the previous line. Verification
 * checks schema, seal, and linkage and names the first broken line (1-based).
 */
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
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

const LOCK_WAIT_MS = 15_000;
const LOCK_STALE_MS = 30_000;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** A lock is stale only when it is old and its owner process is gone. */
function lockIsStale(lock: string): boolean {
  try {
    const age = Date.now() - statSync(lock).mtimeMs;
    if (age < LOCK_STALE_MS) return false;
    const pid = Number(readFileSync(lock, "utf8").split(" ")[0]);
    return !Number.isInteger(pid) || pid <= 0 || !pidAlive(pid);
  } catch {
    return false;
  }
}

/**
 * One writer at a time per trace (S63). Two hook processes that opened the same
 * trace used to each seal their Decision against the same predecessor, so both
 * succeeded and the chain no longer verified. The lock covers read-last, seal,
 * append and head rewrite as one step.
 */
function withLock<T>(tracePath: string, fn: () => T): T {
  const lock = tracePath + ".lock";
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lock, "wx");
      writeFileSync(fd, `${process.pid} ${Date.now()}\n`);
      closeSync(fd);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      if (lockIsStale(lock)) {
        try {
          rmSync(lock);
        } catch {
          // another process removed it first
        }
        continue;
      }
      if (Date.now() > deadline) throw new Error(`trace lock ${lock} held for over ${LOCK_WAIT_MS / 1000}s`);
      sleepSync(5);
    }
  }
  try {
    return fn();
  } finally {
    try {
      rmSync(lock);
    } catch {
      // already gone
    }
  }
}

export class TraceWriter {
  private last: Decision | null = null;
  private count = 0;

  constructor(public readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    withLock(path, () => {
      if (existsSync(path)) {
        // Resuming an existing trace: it must verify (including its seal, if any) or we refuse to append to it.
        const v = verifyTrace(path);
        if (!v.ok) throw new Error(`refusing to append to a trace that does not verify: ${v.reason}`);
      }
      this.reload();
    });
  }

  /** Re-read the tail from disk. Called under the lock, so what it reads is what the next append must link to. */
  private reload(): void {
    if (!existsSync(this.path)) {
      this.last = null;
      this.count = 0;
      return;
    }
    const lines = readFileSync(this.path, "utf8").split("\n").filter((l) => l.trim().length > 0);
    this.count = lines.length;
    this.last = lines.length > 0 ? (JSON.parse(lines[lines.length - 1]!) as Decision) : null;
  }

  /** Write the head atomically (temp file, then rename) so a concurrent reader never sees half of it. */
  private writeHead(now: Date): TraceHead {
    const head: TraceHead = { trace_head_version: "0.1.0", lines: this.count, last_sha256: this.last?.this_sha256 ?? null, sealed_at: now.toISOString() };
    const hp = headPath(this.path);
    const tmp = `${hp}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(head, null, 2) + "\n");
    renameSync(tmp, hp);
    return head;
  }

  /** Write the terminal commitment from what is on disk now, so truncation is detectable. */
  seal(now: Date = new Date()): TraceHead {
    return withLock(this.path, () => {
      this.reload();
      return this.writeHead(now);
    });
  }

  append(draft: DecisionDraft): Decision {
    return withLock(this.path, () => {
      this.reload();
      const sealed = sealDecision(draft, this.last);
      appendFileSync(this.path, JSON.stringify(sealed) + "\n");
      this.last = sealed;
      this.count += 1;
      this.writeHead(new Date());
      return sealed;
    });
  }

  /** Lines on disk as of the last read or append by this writer. */
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
