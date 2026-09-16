import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { normalizeAgentcoreDogwood } from "../packages/adapters/agentcore-dogwood/index.ts";
import { loadCatalog, type ControlResult } from "../packages/catalog/checks.ts";
import {
  CONTROL_FRAMEWORK,
  RESOURCE_TYPE,
  buildFinding,
  connectorSource,
  findingsFromDir,
  validateFinding,
  writeFindings,
} from "../packages/export/finding/index.ts";
import { argsSha256, redactArgs, sealDecision, type Decision, type DecisionDraft } from "../packages/normalize/decision.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";
import { TraceWriter } from "../packages/trace/trace.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");

function draft(over: Partial<DecisionDraft> & Pick<DecisionDraft, "effect" | "rule_ids" | "tool">): DecisionDraft {
  const args = { path: "x" };
  return {
    source: over.source ?? "colophon-gate",
    effect: over.effect,
    rule_ids: over.rule_ids,
    reasons: over.reasons ?? [{ field: "tools[].name", value: over.tool }],
    tool: over.tool,
    args_sha256: argsSha256(args),
    args_redacted: redactArgs(args),
    session_id: over.session_id ?? "sess-export-01",
    call_index: over.call_index ?? 0,
    ts: over.ts ?? "2026-09-14T12:00:00.000Z",
  };
}

function sealed(over: Parameters<typeof draft>[0], prev: Decision | null = null): Decision {
  return sealDecision(draft(over), prev);
}

describe("finding export", () => {
  test("connector source slugs match the club pattern", () => {
    expect(connectorSource("colophon-gate")).toBe("colophon");
    expect(connectorSource("agentcore-dogwood")).toBe("colophon-agentcore-dogwood");
    expect(connectorSource("claude-hook")).toBe("colophon-claude-hook");
    expect(connectorSource("aws-config")).toBe("colophon-aws-config");
  });

  test("agentcore-dogwood fixture decisions produce a schema-valid Finding", () => {
    const n = normalizeAgentcoreDogwood(join(FIX, "agentcore-dogwood", "session.jsonl"));
    const record = buildRecord(loadDeclaration(join(FIX, "declarations", "red-team-coder.yaml")));
    let prev: Decision | null = null;
    const decisions = n.drafts.map((d) => {
      prev = sealDecision({ ...d, record_sha256: record.canonical_sha256 }, prev);
      return prev;
    });
    const catalog = loadCatalog();
    const catalogResults: ControlResult[] = catalog.controls
      .filter((c) => c.phase === "assess")
      .map((c) => ({
        control: c,
        state: c.id === "COL-02" ? "not-satisfied" : "satisfied",
        rationale: c.id === "COL-02" ? "No fail-closed self-test on a foreign PEP." : `${c.id} satisfied in fixture.`,
        cited: ["deadbeef"],
      }));
    const doc = buildFinding({
      decisions,
      sessionId: n.sessionId,
      source: "agentcore-dogwood",
      record,
      catalogResults,
      task: n.task,
    });
    expect(validateFinding(doc).ok).toBe(true);
    expect(doc.schema_version).toBe("1.0.0");
    expect(doc.source).toBe("colophon-agentcore-dogwood");
    expect(doc.source_version).toBe("0.1.0");
    expect(doc.resource.type).toBe(RESOURCE_TYPE);
    expect(doc.resource.id).toBe("ac-roe-0001");
    expect(doc.resource.pep_source).toBe("agentcore-dogwood");
    expect(doc.resource.tags?.["enforcement_mode"]).toBe("ENFORCE");
    const col = doc.evaluations.filter((e) => /^COL-\d+$/.test(e.control_id));
    expect(col.some((e) => e.control_id === "COL-01" && e.status === "pass")).toBe(true);
    expect(col.some((e) => e.control_id === "COL-02" && e.status === "fail" && e.message)).toBe(true);
    const pep = doc.evaluations.filter((e) => e.assessed_at);
    expect(pep.some((e) => e.status === "pass" && e.control_id === "DW-PERMIT-IN-SCOPE-READ")).toBe(true);
    expect(pep.some((e) => e.status === "fail" && e.control_id === "DW-OUT-OF-SCOPE" && e.message)).toBe(true);
    expect(doc.evaluations.every((e) => e.control_framework === CONTROL_FRAMEWORK)).toBe(true);
    expect(JSON.stringify(doc)).not.toContain("SCF");
    expect(doc.evaluations.some((e) => e.control_framework === "SCF")).toBe(false);
  });

  test("allow/deny/escalate map only to schema enums; fail and inconclusive carry a message", () => {
    const a = sealed({ effect: "allow", rule_ids: ["COL-GATE-ALLOW"], tool: "repo.list" });
    const d = sealed({ effect: "deny", rule_ids: ["COL-GATE-SANDBOX"], tool: "fs.write", call_index: 1, session_id: a.session_id }, a);
    const e = sealed({ effect: "escalate", rule_ids: ["COL-GATE-APPROVAL"], tool: "mail.send", call_index: 2, session_id: a.session_id }, d);
    const doc = buildFinding({ decisions: [a, d, e], sessionId: "sess-export-01", source: "colophon-gate" });
    expect(validateFinding(doc).ok).toBe(true);
    expect(doc.source).toBe("colophon");
    const pep = doc.evaluations.filter((x) => x.assessed_at);
    expect(pep.map((x) => `${x.control_id}:${x.status}`)).toEqual([
      "COL-GATE-ALLOW:pass",
      "COL-GATE-SANDBOX:fail",
      "COL-GATE-APPROVAL:inconclusive",
    ]);
    expect(pep.filter((x) => x.status === "fail" || x.status === "inconclusive").every((x) => (x.message ?? "").length > 0)).toBe(true);
  });

  test("empty input fails closed with inconclusive COL-04, never a vacuous pass", () => {
    const doc = buildFinding({ decisions: [], sessionId: "empty-session", source: "colophon-gate" });
    expect(validateFinding(doc).ok).toBe(true);
    expect(doc.evaluations).toHaveLength(1);
    expect(doc.evaluations[0]!.control_id).toBe("COL-04");
    expect(doc.evaluations[0]!.status).toBe("inconclusive");
    expect(doc.evaluations[0]!.message).toMatch(/refusing to report pass or fail/);
  });

  test("schema rejects invented fields; exporter throws rather than write them", () => {
    const a = sealed({ effect: "allow", rule_ids: ["COL-GATE-ALLOW"], tool: "repo.list" });
    const doc = buildFinding({ decisions: [a], sessionId: "sess-export-01", source: "colophon-gate" });
    expect(validateFinding({ ...doc, invented: true }).ok).toBe(false);
    expect(validateFinding({ ...doc, schema_version: "1.0.1" }).ok).toBe(false);
    expect(validateFinding({ ...doc, evaluations: [{ control_framework: "Colophon", control_id: "COL-01", status: "okay" }] }).ok).toBe(false);
  });

  test("CLI-shaped --from a sealed agentcore trace writes a valid file", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-find-"));
    const n = normalizeAgentcoreDogwood(join(FIX, "agentcore-dogwood", "session.jsonl"));
    const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
    const w = new TraceWriter(tracePath);
    for (const d of n.drafts) w.append(d);
    w.seal();
    const docs = findingsFromDir({ from: dir });
    expect(docs).toHaveLength(1);
    expect(validateFinding(docs[0]!).ok).toBe(true);
    expect(docs[0]!.source).toBe("colophon-agentcore-dogwood");
    expect(docs[0]!.resource.type).toBe("ai_agent_session");
    expect(docs[0]!.resource.id).toBe("ac-roe-0001");
    const out = join(dir, "findings");
    const written = writeFindings(out, docs);
    expect(written).toHaveLength(1);
    const round = JSON.parse(readFileSync(written[0]!.path, "utf8"));
    expect(validateFinding(round).ok).toBe(true);
    expect(readdirSync(out).some((n) => n.endsWith(".finding.json"))).toBe(true);
  });

  test("live APPLICATION_LOGS session exports a Finding keyed by sidecar session_id", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-find-live-"));
    const n = normalizeAgentcoreDogwood(join(FIX, "agentcore-dogwood", "live-roe-7461903f.jsonl"));
    const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
    const w = new TraceWriter(tracePath);
    for (const d of n.drafts) w.append(d);
    w.seal();
    const docs = findingsFromDir({ from: dir });
    expect(docs).toHaveLength(1);
    expect(validateFinding(docs[0]!).ok).toBe(true);
    expect(docs[0]!.resource.id).toBe("7461903f-e0c0-41ce-844b-87d43dcb1a23");
    expect(docs[0]!.evaluations.filter((e) => e.status === "fail").length).toBe(2);
    expect(docs[0]!.evaluations.filter((e) => e.status === "pass").length).toBeGreaterThanOrEqual(3);
  });

  test("refuses an unsealed trace", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-find-unsealed-"));
    const n = normalizeAgentcoreDogwood(join(FIX, "agentcore-dogwood", "session.jsonl"));
    const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
    const w = new TraceWriter(tracePath);
    for (const d of n.drafts) w.append(d);
    rmSync(tracePath + ".head.json");
    expect(() => findingsFromDir({ from: dir })).toThrow(/unsealed/);
  });
});
