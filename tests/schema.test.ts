import { describe, expect, test } from "bun:test";
import { join, resolve } from "node:path";
import { buildRecord, loadDeclaration, verifyRecordHashes } from "../packages/schema/record.ts";
import { validateDeclaration } from "../packages/schema/validate.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");

describe("declaration schema", () => {
  test("shipped declarations validate", () => {
    for (const f of ["evidence-reader.yaml", "notifier.yaml"]) expect(() => loadDeclaration(join(FIX, "declarations", f))).not.toThrow();
  });
  test("missing owner is named", () => {
    expect(() => loadDeclaration(join(FIX, "declarations", "bad", "missing-owner.yaml"))).toThrow(/owner/);
  });
  test("all-zero uuid and unknown autonomy level are rejected", () => {
    const d = loadDeclaration(join(FIX, "declarations", "notifier.yaml"));
    expect(validateDeclaration({ ...d, id: "00000000-0000-0000-0000-000000000000" }).ok).toBe(false);
    expect(validateDeclaration({ ...d, autonomy_level: "L9" }).ok).toBe(false);
    expect(validateDeclaration({ ...d, extra: 1 }).ok).toBe(false);
  });
});

describe("record", () => {
  test("hashes recompute and a tampered field is caught", () => {
    const r = buildRecord(loadDeclaration(join(FIX, "declarations", "notifier.yaml")));
    expect(verifyRecordHashes(r)).toBeNull();
    expect(verifyRecordHashes({ ...r, canonical_sha256: "0".repeat(64) })).toMatch(/canonical_sha256 mismatch/);
    expect(verifyRecordHashes({ ...r, declaration: { ...r.declaration, owner: "x@y.example" } })).toMatch(/declaration_sha256 mismatch/);
  });
});
