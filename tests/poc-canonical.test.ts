/**
 * S60: Colophon's RFC 8785 canonicalizer agrees with the canonical-form
 * vectors the Proof-of-Control Standard publishes. The vectors and the
 * expected digests are vendored unmodified (packages/fixtures/proof-of-control/SOURCE.md).
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalize, canonicalSha256 } from "../packages/schema/canonical.ts";

const ROOT = resolve(import.meta.dir, "../packages/fixtures/proof-of-control/vectors");
const manifest = JSON.parse(readFileSync(resolve(ROOT, "manifest.json"), "utf8")) as { canonical: { file: string; canonical_sha256: string; description: string }[] };

describe("Proof-of-Control canonical-form vectors (S60)", () => {
  test("the manifest lists the two canonical vectors", () => {
    expect(manifest.canonical.map((v) => v.file).sort()).toEqual(["canonical/nonbmp-key-ordering.json", "canonical/tricky-strings.json"]);
  });

  for (const v of manifest.canonical) {
    test(`${v.file}: canonicalSha256 equals the standard's digest (${v.description})`, () => {
      const value = JSON.parse(readFileSync(resolve(ROOT, v.file), "utf8"));
      expect(canonicalSha256(value)).toBe(v.canonical_sha256);
    });
  }

  test("keys outside the BMP sort by UTF-16 code unit, not by code point", () => {
    const value = JSON.parse(readFileSync(resolve(ROOT, "canonical/nonbmp-key-ordering.json"), "utf8"));
    // U+1F600 is the surrogate pair D83D DE00, which sorts below U+FF00 by code unit and above it by code point.
    expect(canonicalize(value)).toBe('{"a":"ascii","\u{1F600}":"astral","＀":"bmp"}');
  });

  test("a wrong digest would fail: the comparison is not vacuous", () => {
    const value = JSON.parse(readFileSync(resolve(ROOT, "canonical/tricky-strings.json"), "utf8"));
    expect(canonicalSha256({ ...value, ascii: "changed" })).not.toBe(manifest.canonical.find((v) => v.file.endsWith("tricky-strings.json"))!.canonical_sha256);
  });
});
