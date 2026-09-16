/**
 * A packet whose COL-10 (no credential values) is not-satisfied is refused
 * before signing. The refusal happens before cosign is invoked, so this test
 * needs no key and no cosign: a signer pointing at nonexistent files proves
 * the throw came first.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPacket } from "../packages/cli/packet.ts";
import { argsSha256, type DecisionDraft } from "../packages/normalize/decision.ts";
import { sha256Hex } from "../packages/schema/canonical.ts";
import { TraceWriter } from "../packages/trace/trace.ts";

describe("packet refuses to sign a credential leak", () => {
  test("COL-10 not-satisfied → no bundle, no stage, error names the control", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-refuse-"));
    const tracePath = join(dir, "trace", "leak.jsonl");
    // Built at runtime so no committed literal resembles a real token. Written
    // straight into args_redacted to simulate a redaction gap: the sealed view
    // itself carries the value.
    const fake = ["gh", "p_", "LEAK", "B".repeat(32)].join("");
    const w = new TraceWriter(tracePath);
    const draft: DecisionDraft = {
      source: "claude-hook",
      effect: "allow",
      rule_ids: ["CC-HOOK-CWD"],
      reasons: [{ field: "tool_input.command", value: "curl …" }],
      tool: "Bash",
      args_sha256: argsSha256({ command: fake }),
      args_redacted: { command: `curl -H "Authorization: Bearer ${fake}" https://api.github.example` },
      session_id: "leak",
      call_index: 0,
      ts: "2026-09-15T00:00:00Z",
    };
    w.append(draft);
    w.seal();
    const outRoot = join(dir, "out");
    expect(() =>
      buildPacket({
        name: "leak",
        source: "claude-hook",
        sessionId: "leak",
        task: "leak test",
        outRoot,
        tracePath,
        signer: { mode: "key", key: join(dir, "no.key"), pub: join(dir, "no.pub"), password: "x", signingConfig: join(dir, "no.json") },
      }),
    ).toThrow(/refusing to sign leak: COL-10 not-satisfied/);
    expect(existsSync(join(outRoot, "leak", "bundle"))).toBe(false);
    expect(existsSync(join(outRoot, "leak", "stage"))).toBe(false);
    expect(readdirSync(join(outRoot, "leak"))).toEqual([]);
    // The commitment of the same value is what a redacted view would carry.
    expect(sha256Hex(fake)).toMatch(/^[0-9a-f]{64}$/);
  });
});
