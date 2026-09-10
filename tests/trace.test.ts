import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { argsSha256, redactArgs, sealDecision, type Decision } from "../packages/normalize/decision.ts";
import { headPath, TraceWriter, verifyTrace } from "../packages/trace/trace.ts";
import { canonicalize, sha256Hex } from "../packages/schema/canonical.ts";

const draft = (i: number) => ({ source: "test", effect: "allow" as const, rule_ids: ["T"], reasons: [{ field: "f", value: i }], tool: "t", args_sha256: argsSha256({ i }), ts: "2026-09-10T00:00:00Z", call_index: i });

describe("canonicalize", () => {
  test("sorts keys and strips whitespace", () => {
    expect(canonicalize({ b: [1, { z: null, a: "x" }], a: true })).toBe('{"a":true,"b":[1,{"a":"x","z":null}]}');
  });
});

describe("redaction", () => {
  test("secret-looking keys and values are replaced, others kept", () => {
    // Built at runtime so no committed literal resembles a real token.
    const fake = ["gh", "p_", "FAKE", "0".repeat(32)].join("");
    const r = redactArgs({ path: "/x", token: "abc", note: fake, scopes: ["repo:read"] });
    expect(r["path"]).toBe("/x");
    expect(r["scopes"]).toEqual(["repo:read"]);
    expect(r["token"]).toBe("sha256:" + sha256Hex("abc"));
    expect(r["note"]).toBe("sha256:" + sha256Hex(fake));
    expect(JSON.stringify(r)).not.toContain(fake);
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

  test("a sealed trace detects truncation of its last lines", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-trace-"));
    const p = join(dir, "t.jsonl");
    const w = new TraceWriter(p);
    for (let i = 0; i < 4; i++) w.append(draft(i));
    w.seal();
    expect(verifyTrace(p)).toMatchObject({ ok: true, sealed: true });
    const lines = readFileSync(p, "utf8").split("\n").filter(Boolean);
    writeFileSync(p, lines.slice(0, 3).join("\n") + "\n");
    const v = verifyTrace(p);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/seal says 4 lines, trace has 3/);
    expect(() => new TraceWriter(p)).toThrow(/does not verify/);
  });

  test("a trace whose head commitment was removed verifies but reports sealed: false (and the packet refuses it)", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-trace-"));
    const p = join(dir, "t.jsonl");
    new TraceWriter(p).append(draft(0));
    expect(verifyTrace(p)).toMatchObject({ ok: true, sealed: true });
    rmSync(headPath(p));
    expect(verifyTrace(p)).toMatchObject({ ok: true, sealed: false });
  });

  test("sealDecision validates the schema", () => {
    const bad = { ...draft(0), effect: "maybe" } as unknown as Parameters<typeof sealDecision>[0];
    expect(() => sealDecision(bad, null as Decision | null)).toThrow(/decision invalid/);
  });
});
