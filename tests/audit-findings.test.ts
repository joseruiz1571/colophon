/**
 * F14: four findings a second-vendor read of docs/proof-of-control.md raised and
 * probes confirmed (S61 to S64). Each test name starts with its claim id so the
 * probe can select it. Needs opa on the path, as the hook tests do.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decide, decideBound } from "../packages/gate/eval.ts";
import { canonicalPath } from "../packages/gate/paths.ts";
import { mapCall } from "../packages/hook/index.ts";
import { argsSha256, redactArgs } from "../packages/normalize/decision.ts";
import { sha256Hex } from "../packages/schema/canonical.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";
import { TraceWriter, verifyTrace } from "../packages/trace/trace.ts";

const ROOT = resolve(import.meta.dir, "..");
const decl = loadDeclaration(join(ROOT, "packages/fixtures/declarations/evidence-reader.yaml"));
const record = buildRecord(decl);
const ctx = { session_id: "t", call_index: 0 };
const write = (path: string, rec = record, context: Record<string, unknown> = ctx) => decide(rec, { name: "fs.write", arguments: { path, data_class: "internal" } }, context as typeof ctx);
const tmp = (p: string) => mkdtempSync(join(tmpdir(), p));

describe("S61 the sandbox check sees the real location of a path", () => {
  test("S61 a link inside the sandbox that points outside is denied; ordinary paths are unchanged", () => {
    const w = tmp("s61-work-");
    const o = tmp("s61-outside-");
    mkdirSync(join(w, "out/evidence-reader"), { recursive: true });
    symlinkSync(o, join(w, "out/evidence-reader/escape"));
    const through = mapCall({ session_id: "s", cwd: w, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(w, "out/evidence-reader/escape/x.txt") } }, undefined).arguments["path"] as string;
    expect(through).toBe(join(realpathSync(o), "x.txt"));
    expect(write(through).effect).toBe("deny");
    expect(write(through).rule_ids).toContain("COL-GATE-SANDBOX");
    expect(write(canonicalPath(w, "out/evidence-reader/a.txt")).effect).toBe("allow");
    expect(canonicalPath(w, "out/evidence-reader/../x")).toBe("out/x");
    expect(write(canonicalPath(w, "out/evidence-reader-evil/x")).effect).toBe("deny");
  });

  test("S61 a dangling link is followed too, because a write through it creates its target", () => {
    const w = tmp("s61-dangle-");
    const o = tmp("s61-dangle-out-");
    mkdirSync(join(w, "out/evidence-reader"), { recursive: true });
    symlinkSync(join(o, "not-yet"), join(w, "out/evidence-reader/dangling"));
    const p = canonicalPath(w, "out/evidence-reader/dangling/file.txt");
    expect(p).toBe(join(realpathSync(o), "not-yet", "file.txt"));
    expect(write(p).effect).toBe("deny");
  });

  test("S61 a link that stays inside the sandbox is allowed, and a symlinked cwd is not a false denial", () => {
    const real = tmp("s61-real-");
    mkdirSync(join(real, "out/evidence-reader/sub"), { recursive: true });
    symlinkSync(join(real, "out/evidence-reader/sub"), join(real, "out/evidence-reader/alias"));
    expect(canonicalPath(real, "out/evidence-reader/alias/f.txt")).toBe("out/evidence-reader/sub/f.txt");
    const linkedCwd = join(tmp("s61-cwdlink-"), "cwd");
    symlinkSync(real, linkedCwd);
    expect(canonicalPath(linkedCwd, "out/evidence-reader/f.txt")).toBe("out/evidence-reader/f.txt");
    expect(write(canonicalPath(linkedCwd, "out/evidence-reader/f.txt")).effect).toBe("allow");
  });
});

describe("S62 the review date is enforced on every call", () => {
  test("S62 a past-due Record is denied by the policy on a live call, with no startup involved", () => {
    const stale = buildRecord({ ...decl, review_due: "2020-01-01" });
    const v = write("out/evidence-reader/a.txt", stale);
    expect(v.effect).toBe("deny");
    expect(v.rule_ids).toContain("COL-GATE-STALE");
    expect(write("out/evidence-reader/a.txt").effect).toBe("allow");
  });

  test("S62 a re-evaluation of a recorded Decision asks at that Decision's time, so an old packet still re-checks", () => {
    const stale = buildRecord({ ...decl, review_due: "2020-01-01" });
    expect(write("out/evidence-reader/a.txt", stale, { ...ctx, as_of: "2019-12-31T00:00:00Z" }).effect).toBe("allow");
    expect(write("out/evidence-reader/a.txt", stale, { ...ctx, as_of: "2020-01-02T00:00:00Z" }).rule_ids).toContain("COL-GATE-STALE");
  });
});

describe("S63 concurrent writers cannot break a trace", () => {
  const draft = (i: number) => {
    const a = { path: `out/evidence-reader/f${i}.txt`, data_class: "internal" };
    return { source: "colophon-gate", effect: "allow" as const, rule_ids: ["COL-GATE-ALLOW"], reasons: [{ field: "tools[].name", value: "fs.write" }], tool: "fs.write", args_sha256: argsSha256(a), args_redacted: redactArgs(a), session_id: "s63", call_index: i, record_sha256: record.canonical_sha256, ts: new Date().toISOString() };
  };

  test("S63 two writers opened before either appends both link correctly", () => {
    const p = join(tmp("s63-a-"), "t.jsonl");
    new TraceWriter(p).append(draft(0));
    const a = new TraceWriter(p);
    const b = new TraceWriter(p);
    a.append(draft(1));
    b.append(draft(2));
    expect(verifyTrace(p)).toMatchObject({ ok: true, lines: 3, sealed: true });
    expect(existsSync(p + ".lock")).toBe(false);
  });

  test("S63 four simultaneous processes, repeated: every append lands, the chain verifies, no lock is left", async () => {
    const N = 4;
    for (let round = 0; round < 6; round++) {
      const d = tmp("s63-b-");
      const p = join(d, "t.jsonl");
      new TraceWriter(p).append(draft(0));
      const start = Date.now() + 500;
      const kids = Array.from({ length: N }, (_, i) => Bun.spawn(["bun", join(ROOT, "tests/trace-child.ts"), p, String(start), String(i + 1), record.canonical_sha256], { stdout: "ignore", stderr: "pipe" }));
      const codes = await Promise.all(kids.map((k) => k.exited));
      expect(codes).toEqual(Array(N).fill(0));
      expect(verifyTrace(p)).toMatchObject({ ok: true, lines: N + 1, sealed: true });
      expect(readdirSync(d).filter((f) => f.endsWith(".lock") || f.endsWith(".tmp"))).toEqual([]);
      rmSync(d, { recursive: true, force: true });
    }
  }, 60_000);

  test("S63 a lock left by a dead process is taken over; one held by a live process is not", () => {
    const p = join(tmp("s63-c-"), "t.jsonl");
    writeFileSync(p + ".lock", "999999 0\n");
    const old = new Date(Date.now() - 120_000);
    utimesSync(p + ".lock", old, old);
    new TraceWriter(p).append(draft(0));
    expect(verifyTrace(p)).toMatchObject({ ok: true, lines: 1 });
  });
});

describe("S64 the hash names the bytes that decided", () => {
  test("S64 with the policy file swapped every millisecond, no verdict is credited to the other policy's hash", async () => {
    const dir = tmp("s64-");
    const p1 = join(dir, "p1.rego");
    const p2 = join(dir, "p2.rego");
    const live = join(dir, "gate.rego");
    const text = readFileSync(join(ROOT, "packages/policy/gate.rego"), "utf8");
    writeFileSync(p1, text);
    writeFileSync(p2, text + `\ndenies contains {"rule_id": "COL-PROBE-P2", "reason": {"field": "probe", "value": "p2"}} if { true }\n`);
    writeFileSync(live, text);
    const h1 = sha256Hex(readFileSync(p1));
    const h2 = sha256Hex(readFileSync(p2));
    const swapper = Bun.spawn(["bun", join(ROOT, "tests/policy-swapper.ts"), live, p1, p2], { stdout: "ignore", stderr: "ignore" });
    await Bun.sleep(300);
    let from1 = 0;
    let from2 = 0;
    let wrong = 0;
    for (let i = 0; i < 120; i++) {
      const { verdict, policy_sha256 } = decideBound(record, { name: "fs.write", arguments: { path: "out/evidence-reader/a.txt", data_class: "internal" } }, ctx, live, true);
      const decidedBy = verdict.rule_ids.includes("COL-PROBE-P2") ? h2 : h1;
      decidedBy === h1 ? from1++ : from2++;
      if (policy_sha256 !== decidedBy) wrong++;
    }
    swapper.kill();
    expect(wrong).toBe(0);
    expect(from1 + from2).toBe(120);
    expect(from1).toBeGreaterThan(0);
    expect(from2).toBeGreaterThan(0);
  }, 60_000);

  test("S64 an unreadable policy still fails closed and names no hash", () => {
    const { verdict, policy_sha256 } = decideBound(record, { name: "fs.read", arguments: { data_class: "internal" } }, ctx, "/nonexistent/gate.rego", true);
    expect(verdict.rule_ids).toEqual(["COL-GATE-OPA-ERROR"]);
    expect(policy_sha256).toBeUndefined();
  });
});
