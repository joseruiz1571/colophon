/**
 * COL-11 (policy-bound) never satisfies vacuously and the narrative never
 * outruns it. Built from the cross-vendor audit of the first policy-binding
 * commit: an empty foreign trace, an allow with no rule id, a stray hash, and
 * a gate packet with one unbound decision all read not-satisfied, and the
 * narrative says "staged, not fully bound" instead of "every decision".
 */
import { describe, expect, test } from "bun:test";
import { join, resolve } from "node:path";
import { assess, loadCatalog, type AssessContext, type StagedPolicy } from "../packages/catalog/checks.ts";
import { EvidenceStore } from "../packages/evidence/store.ts";
import { argsSha256, sealDecision, type Decision, type DecisionDraft } from "../packages/normalize/decision.ts";
import { buildNarrative } from "../packages/report/narrative.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");
const roe = buildRecord(loadDeclaration(join(FIX, "declarations", "colophon-roe.yaml")));
const coder = buildRecord(loadDeclaration(join(FIX, "declarations", "claude-coder.yaml")));
const GATE = "1".repeat(64);
const catalog = loadCatalog();

function chain(drafts: DecisionDraft[]): Decision[] {
  const out: Decision[] = [];
  let prev: Decision | null = null;
  for (const d of drafts) {
    prev = sealDecision(d, prev);
    out.push(prev);
  }
  return out;
}

function ctx(source: string, record: typeof roe | null, decisions: Decision[], policies: StagedPolicy[]): AssessContext {
  const store = new EvidenceStore();
  const trace = store.put(source, "trace", { decisions }).id;
  const summary = store.put(source, "session-summary", { n: decisions.length }).id;
  const ids: AssessContext["ids"] = { trace, summary };
  if (record) ids.record = store.put(source, "record", record).id;
  if (policies.length) ids.policies = store.put(source, "policies", { files: policies }).id;
  return { source, record, decisions, trace: { ok: true, lines: decisions.length, sealed: true } as AssessContext["trace"], store, ids, narrative: "", policies };
}

const col11 = (c: AssessContext) => assess(c, catalog).find((r) => r.control.id === "COL-11")!;

const declaredStaged: StagedPolicy[] = roe.declaration.pep!.policies!.map((p) => ({ role: "declared", id: p.id, kind: p.kind, path: `policy/${p.id}.cedar`, sha256: p.sha256 }));
const permit = roe.declaration.pep!.policies![0]!.id;

const foreign = (over: Partial<DecisionDraft>): DecisionDraft => ({
  source: "agentcore-dogwood",
  effect: "allow",
  rule_ids: [permit],
  reasons: [{ field: "input", value: {} }],
  tool: "StatusTarget___get_status",
  args_sha256: argsSha256({}),
  args_redacted: {},
  session_id: "t",
  call_index: 0,
  record_sha256: roe.canonical_sha256,
  ts: "2026-09-25T00:00:00Z",
  ...over,
});

describe("COL-11 foreign branch fails closed", () => {
  test("declared and staged, one allow citing a declared permit → satisfied", () => {
    const r = col11(ctx("agentcore-dogwood", roe, chain([foreign({})]), declaredStaged));
    expect(r.state).toBe("satisfied");
  });
  test("empty trace → not-satisfied (not exercised)", () => {
    const r = col11(ctx("agentcore-dogwood", roe, [], declaredStaged));
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/no decisions/);
  });
  test("allow with no rule id → not-satisfied (undeclared permit)", () => {
    const r = col11(ctx("agentcore-dogwood", roe, chain([foreign({ rule_ids: [] })]), declaredStaged));
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/cite no policy id/);
  });
  test("allow citing a permit the Record does not declare → not-satisfied", () => {
    const r = col11(ctx("agentcore-dogwood", roe, chain([foreign({ rule_ids: ["permit_something_else-abc"] })]), declaredStaged));
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/does not declare: permit_something_else-abc/);
  });
  test("decision carrying a policy_sha256 that matches no staged file → not-satisfied", () => {
    const r = col11(ctx("agentcore-dogwood", roe, chain([foreign({ policy_sha256: "a".repeat(64) })]), declaredStaged));
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/matches no policy staged/);
  });
  test("a declared policy not staged → not-satisfied", () => {
    const r = col11(ctx("agentcore-dogwood", roe, chain([foreign({})]), declaredStaged.slice(1)));
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/1 of 3 declared policies are not staged/);
  });
});

const gateDraft = (i: number, hash: string | undefined): DecisionDraft => ({
  source: "colophon-hook",
  effect: "allow",
  rule_ids: ["COL-GATE-ALLOW"],
  reasons: [{ field: "tools[].name", value: "fs.read" }],
  tool: "fs.read",
  args_sha256: argsSha256({ path: `src/${i}.ts` }),
  args_redacted: { path: `src/${i}.ts` },
  session_id: "g",
  call_index: i,
  record_sha256: coder.canonical_sha256,
  ...(hash ? { policy_sha256: hash } : {}),
  ts: "2026-09-25T00:00:00Z",
});
const gateStaged: StagedPolicy[] = [{ role: "gate", path: "policy/gate.rego", sha256: GATE }];

describe("COL-11 Colophon branch and the narrative agree", () => {
  test("all decisions bound → satisfied, narrative says every decision", () => {
    const decisions = chain([gateDraft(0, GATE), gateDraft(1, GATE)]);
    const c = ctx("colophon-hook", coder, decisions, gateStaged);
    const results = assess(c, catalog);
    expect(results.find((r) => r.control.id === "COL-11")!.state).toBe("satisfied");
    const n = buildNarrative({ source: "colophon-hook", sessionId: "g", record: coder, task: "t", decisions, results, traceOk: true, verifyCommand: "x", policies: gateStaged });
    expect(n).toMatch(/Policy bound: every decision carries/);
    expect(n).toMatch(/Each verdict is bound, by hash/);
  });
  test("one unbound decision → not-satisfied, narrative says staged, not fully bound", () => {
    const decisions = chain([gateDraft(0, GATE), gateDraft(1, undefined), gateDraft(2, GATE)]);
    const c = ctx("colophon-hook", coder, decisions, gateStaged);
    const results = assess(c, catalog);
    const r = results.find((rr) => rr.control.id === "COL-11")!;
    expect(r.state).toBe("not-satisfied");
    expect(r.rationale).toMatch(/1 of 3 decisions are not bound/);
    const n = buildNarrative({ source: "colophon-hook", sessionId: "g", record: coder, task: "t", decisions, results, traceOk: true, verifyCommand: "x", policies: gateStaged });
    expect(n).not.toMatch(/every decision carries/);
    expect(n).toMatch(/Policy staged, not fully bound: `policy\/gate.rego`.*1 of 3 decisions/);
    expect(n).toMatch(/not every verdict is bound to it; COL-11 reads not-satisfied/);
    expect(n).not.toMatch(/Each verdict is bound, by hash/);
  });
  test("nothing staged → not-satisfied, narrative says no policy text staged", () => {
    const decisions = chain([gateDraft(0, undefined)]);
    const c = ctx("colophon-hook", coder, decisions, []);
    const results = assess(c, catalog);
    expect(results.find((r) => r.control.id === "COL-11")!.state).toBe("not-satisfied");
    const n = buildNarrative({ source: "colophon-hook", sessionId: "g", record: coder, task: "t", decisions, results, traceOk: true, verifyCommand: "x", policies: [] });
    expect(n).toMatch(/No policy text is staged in this packet; COL-11 reads not-satisfied/);
  });
});
