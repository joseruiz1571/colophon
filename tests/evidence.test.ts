import { describe, expect, test } from "bun:test";
import { EvidenceError, EvidenceStore } from "../packages/evidence/store.ts";
import { canonicalSha256 } from "../packages/schema/canonical.ts";

describe("EvidenceStore", () => {
  test("id and sha256 are the SHA-256 of the canonical payload", () => {
    const s = new EvidenceStore();
    const item = s.put("test", "thing", { b: 2, a: 1 });
    expect(item.id).toBe(canonicalSha256({ a: 1, b: 2 }));
    expect(item.sha256).toBe(item.id);
  });

  test("rejects a duplicate id", () => {
    const s = new EvidenceStore();
    s.put("test", "thing", { x: 1 });
    expect(() => s.put("test", "thing", { x: 1 })).toThrow(EvidenceError);
    expect(() => s.put("other", "kind", { x: 1 })).toThrow(/duplicate/);
  });

  test("rejects an item whose sha256 does not match its payload (mismatch)", () => {
    const s = new EvidenceStore();
    const good = new EvidenceStore().put("t", "k", { v: 1 });
    expect(() => s.add({ ...good, sha256: "0".repeat(64) })).toThrow(/sha256 mismatch/);
    expect(() => s.add({ ...good, id: "0".repeat(64) })).toThrow(/not the payload hash/);
    expect(s.add(good).id).toBe(good.id);
  });

  test("assertCited names every missing id", () => {
    const s = new EvidenceStore();
    const a = s.put("t", "k", { a: 1 });
    expect(() => s.assertCited([a.id])).not.toThrow();
    expect(() => s.assertCited([a.id, "f".repeat(64)])).toThrow(/f{64}/);
  });
});
