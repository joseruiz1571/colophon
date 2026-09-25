/**
 * A packet whose COL-10 (no credential values) is not-satisfied is refused
 * before signing. The refusal happens before cosign is invoked, so this test
 * needs no key and no cosign: a signer pointing at nonexistent files proves
 * the throw came first.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildPacket } from "../packages/cli/packet.ts";
import { argsSha256, type DecisionDraft } from "../packages/normalize/decision.ts";
import { sha256Hex } from "../packages/schema/canonical.ts";
import { buildRecord, loadDeclaration, type Declaration } from "../packages/schema/record.ts";
import { TraceWriter } from "../packages/trace/trace.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");

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

describe("packet refuses to sign a policy its verdicts did not come from", () => {
  const noSigner = (dir: string) => ({ mode: "key" as const, key: join(dir, "no.key"), pub: join(dir, "no.pub"), password: "x", signingConfig: join(dir, "no.json") });

  test("a Colophon-PEP trace whose policy_sha256 is not the gate policy on disk → no bundle, error names policy_sha256", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-policy-refuse-"));
    const tracePath = join(dir, "trace", "stale.jsonl");
    const w = new TraceWriter(tracePath);
    const draft: DecisionDraft = {
      source: "colophon-hook",
      effect: "allow",
      rule_ids: ["COL-GATE-ALLOW"],
      reasons: [{ field: "tools[].name", value: "fs.read" }],
      tool: "fs.read",
      args_sha256: argsSha256({ path: "src/a.ts" }),
      args_redacted: { path: "src/a.ts" },
      session_id: "stale",
      call_index: 0,
      policy_sha256: "0".repeat(64),
      ts: "2026-09-25T00:00:00Z",
    };
    w.append(draft);
    w.seal();
    const outRoot = join(dir, "out");
    expect(() => buildPacket({ name: "stale", source: "colophon-hook", sessionId: "stale", task: "stale policy test", outRoot, tracePath, signer: noSigner(dir) })).toThrow(/refusing to sign stale: policy_sha256 mismatch/);
    expect(existsSync(join(outRoot, "stale", "bundle"))).toBe(false);
    expect(existsSync(join(outRoot, "stale", "stage"))).toBe(false);
  });

  test("a Record that declares a policy whose file hashes differently → no bundle, error names the policy id", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-policy-refuse-"));
    const decl = loadDeclaration(join(FIX, "declarations", "colophon-roe.yaml"));
    const first = decl.pep!.policies![0]!;
    const tampered: Declaration = { ...decl, pep: { ...decl.pep!, policies: [{ ...first, sha256: "f".repeat(64) }] } };
    const record = buildRecord(tampered);
    const recordPath = join(dir, "colophon-roe.record.json");
    const sigPath = recordPath.replace(/\.record\.json$/, ".record.sigstore.json");
    writeFileSync(recordPath, JSON.stringify(record, null, 2) + "\n");
    writeFileSync(sigPath, "{}\n"); // copied, never verified, before staging runs
    const tracePath = join(dir, "trace", "roe.jsonl");
    const w = new TraceWriter(tracePath);
    w.append({
      source: "agentcore-dogwood",
      effect: "allow",
      rule_ids: [first.id],
      reasons: [{ field: "input", value: {} }],
      tool: "StatusTarget___get_status",
      args_sha256: argsSha256({}),
      args_redacted: {},
      session_id: "roe",
      call_index: 0,
      record_sha256: record.canonical_sha256,
      ts: "2026-09-25T00:00:00Z",
    });
    w.seal();
    const outRoot = join(dir, "out");
    expect(() => buildPacket({ name: "roe", source: "agentcore-dogwood", sessionId: "roe", task: "declared policy test", outRoot, tracePath, record: { path: recordPath, sigPath, record }, signer: noSigner(dir) })).toThrow(new RegExp(`refusing to sign roe: Record colophon-roe declares policy ${first.id} with sha256 ffffffffffff`));
    expect(existsSync(join(outRoot, "roe", "bundle"))).toBe(false);
    expect(existsSync(join(outRoot, "roe", "stage"))).toBe(false);
  });
});
