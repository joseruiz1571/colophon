import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCatalog, type ControlResult } from "../packages/catalog/checks.ts";
import { CitationError, EvidenceStore } from "../packages/evidence/store.ts";
import { buildAssessmentResults } from "../packages/report/oscal.ts";

function input(store: EvidenceStore, results: ControlResult[]) {
  return { title: "t", description: "d", source: "test", sessionId: "s", results, store, evidenceDir: "evidence", extraResources: [], start: "2026-09-10T00:00:00Z", end: "2026-09-10T00:00:01Z" };
}

describe("citation guard", () => {
  const control = loadCatalog().controls[0]!;

  test("refuses to build a report that cites an evidence id not in the store, and writes nothing", () => {
    const store = new EvidenceStore();
    const real = store.put("test", "k", { ok: true });
    const dir = mkdtempSync(join(tmpdir(), "colophon-cite-"));
    const results: ControlResult[] = [{ control, state: "satisfied", rationale: "r", cited: [real.id, "e".repeat(64)] }];
    expect(() => buildAssessmentResults(input(store, results))).toThrow(CitationError);
    try {
      buildAssessmentResults(input(store, results));
    } catch (e) {
      expect((e as CitationError).missing).toEqual(["e".repeat(64)]);
    }
    expect(existsSync(join(dir, "report"))).toBe(false);
    expect(readdirSync(dir)).toEqual([]);
  });

  test("builds when every citation resolves, with an rlink per cited item", () => {
    const store = new EvidenceStore();
    const real = store.put("test", "k", { ok: true });
    const doc = buildAssessmentResults(input(store, [{ control, state: "satisfied", rationale: "r", cited: [real.id] }])) as { "assessment-results": { "back-matter": { resources: { rlinks: { href: string }[] }[] } } };
    expect(doc["assessment-results"]["back-matter"].resources[0]!.rlinks[0]!.href).toBe(`evidence/${real.id}.json`);
  });
});
