import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { argsSha256, redactArgs, sealDecision, type Decision } from "../packages/normalize/decision.ts";
import { TraceWriter, verifyTrace } from "../packages/trace/trace.ts";
import { canonicalize } from "../packages/schema/canonical.ts";

const draft = (i: number) => ({ source: "test", effect: "allow" as const, rule_ids: ["T"], reasons: [{ field: "f", value: i }], tool: "t", args_sha256: argsSha256({ i }), ts: "2026-09-10T00:00:00Z", call_index: i });

describe("canonicalize", () => {
  test("sorts keys and strips whitespace", () => {
    expect(canonicalize({ b: [1, { z: null, a: "x" }], a: true })).toBe('{"a":true,"b":[1,{"a":"x","z":null}]}');
  });
});

describe("redaction", () => {
  test("secret-looking keys and values are replaced, others kept", () => {
    const r = redactArgs({ path: "/x", token: "abc", note: "FAKE-DEMO-CREDENTIAL-do-not-use-0000", scopes: ["repo:read"] });
    expect(r).toEqual({ path: "/x", token: "[REDACTED]", note: "[REDACTED]", scopes: ["repo:read"] });
  });
});

describe("trace chain", () => {
  test("seals, links, and verifies", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-trace-"));
    const p = join(dir, "t.jsonl");
    const w = new TraceWriter(p);
    const a = w.append(draft(0));
    const b = w.append(draft(1));
    expect(a.prev_sha256).toBeNull();
    expect(b.prev_sha256).toBe(a.this_sha256);
    expect(verifyTrace(p)).toMatchObject({ ok: true, lines: 2 });
  });

  test("one altered byte names the line", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-trace-"));
    const p = join(dir, "t.jsonl");
    const w = new TraceWriter(p);
    w.append(draft(0));
    w.append(draft(1));
    w.append(draft(2));
    const lines = readFileSync(p, "utf8").split("\n");
    lines[1] = lines[1]!.replace('"allow"', '"deny"');
    writeFileSync(p, lines.join("\n"));
    const v = verifyTrace(p);
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.line).toBe(2);
      expect(v.reason).toMatch(/line 2/);
    }
  });

  test("a removed line breaks the link of the next", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-trace-"));
    const p = join(dir, "t.jsonl");
    const w = new TraceWriter(p);
    for (let i = 0; i < 3; i++) w.append(draft(i));
    const lines = readFileSync(p, "utf8").split("\n").filter(Boolean);
    writeFileSync(p, [lines[0], lines[2]].join("\n") + "\n");
    const v = verifyTrace(p);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.line).toBe(2);
  });

  test("sealDecision validates the schema", () => {
    const bad = { ...draft(0), effect: "maybe" } as unknown as Parameters<typeof sealDecision>[0];
    expect(() => sealDecision(bad, null as Decision | null)).toThrow(/decision invalid/);
  });
});
