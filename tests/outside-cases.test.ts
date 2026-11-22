/**
 * F15: two outside cases read against the packet (docs/outside-cases.md).
 * S65 is the redaction gap the incident replay found; S66 is the replay
 * itself. Each test name starts with its claim id so the probe can select it.
 * Every token is built at runtime, so no committed literal is shaped like a
 * credential (D24). Needs cosign and opa on the path, as the hook tests do.
 */
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeyPair, offlineSigningConfig, signBlobWithKey } from "../packages/bundle/sign.ts";
import { verifyBundle } from "../packages/bundle/verify.ts";
import { buildPacket } from "../packages/cli/packet.ts";
import { recordSignaturePath } from "../packages/gate/server.ts";
import { runHook, sealSession, tracePathFor } from "../packages/hook/index.ts";
import { argsSha256, CREDENTIAL_PATTERN, redactString, type DecisionDraft } from "../packages/normalize/decision.ts";
import { canonicalSha256, sha256Hex } from "../packages/schema/canonical.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";
import { readTrace, TraceWriter, verifyTrace } from "../packages/trace/trace.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");
// The two Hugging Face shapes gitleaks 8.30.1 detects: a prefix and 34 letters.
const body = "Qz".repeat(17);
const userToken = ["h", "f_", body].join("");
const orgToken = ["api", "_org_", body].join("");

function signedRecord(dir: string): { recordPath: string; pub: string; key: string } {
  const keys = generateKeyPair(join(dir, "keys"), "test");
  const record = buildRecord(loadDeclaration(join(FIX, "declarations", "claude-coder.yaml")));
  const recordPath = join(dir, "claude-coder.record.json");
  writeFileSync(recordPath, JSON.stringify(record, null, 2) + "\n");
  signBlobWithKey({ blob: recordPath, key: keys.key, password: "test", out: recordSignaturePath(recordPath), signingConfig: offlineSigningConfig(join(dir, "keys")) });
  return { recordPath, pub: keys.pub, key: keys.key };
}

/** Every file under `dir`, read as text. */
function filesUnder(dir: string): { path: string; text: string }[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? filesUnder(p) : [{ path: p, text: readFileSync(p, "utf8") }];
  });
}

const event = (session: string, tool: string, input: Record<string, unknown>, id: string) =>
  JSON.stringify({ session_id: session, cwd: "/work/acme-evals", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input, tool_use_id: id });

describe("S65 the credential pattern covers Hugging Face tokens", () => {
  test("S65 a token inside a command is committed in place and the command keeps its shape", () => {
    for (const t of [userToken, orgToken]) {
      expect(CREDENTIAL_PATTERN.test(t)).toBe(true);
      expect(redactString(`HF_TOKEN=${t} bun run eval`)).toBe(`HF_TOKEN=sha256:${sha256Hex(t)} bun run eval`);
    }
    // Ordinary identifiers that begin the same way are not credentials.
    for (const plain of ["from huggingface_hub import hf_hub_download", "pip install hf_transfer", "api_org_id=42"]) expect(redactString(plain)).toBe(plain);
  });

  test("S65 through the hook and the seal, the literal reaches neither the trace nor the packet", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-s65-"));
    const { recordPath, pub, key } = signedRecord(dir);
    const traceDir = join(dir, "hook");
    const r = runHook(event("s65", "Bash", { command: `HF_TOKEN=${userToken} bun run eval` }, "t1"), { recordPath, pubkeyPath: pub, traceDir });
    expect(r.output.hookSpecificOutput.permissionDecision).toBe("ask");
    const raw = readFileSync(tracePathFor(traceDir, "s65"), "utf8");
    expect(raw).not.toContain(userToken);
    expect(raw).toContain(`sha256:${sha256Hex(userToken)}`);
    const p = sealSession({ sessionId: "s65", traceDir, recordPath, pubkeyPath: pub, outRoot: join(dir, "out"), signer: { mode: "key", key, pub, password: "test", signingConfig: offlineSigningConfig(join(dir, "keys")) } });
    expect(verifyBundle({ dir: p.bundleDir, pubkey: pub }).ok).toBe(true);
    expect(filesUnder(p.bundleDir).filter((f) => f.text.includes(userToken)).map((f) => f.path)).toEqual([]);
  }, 60_000);

  test("S65 a sealed view that still carries one is refused before signing under COL-10", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-s65-refuse-"));
    const tracePath = join(dir, "trace", "leak.jsonl");
    // Written straight into args_redacted to simulate a redaction gap, as tests/packet-refuse.test.ts does.
    const draft: DecisionDraft = {
      source: "claude-hook",
      effect: "allow",
      rule_ids: ["CC-HOOK-CWD"],
      reasons: [{ field: "tool_input.command", value: "bun run eval" }],
      tool: "Bash",
      args_sha256: argsSha256({ command: userToken }),
      args_redacted: { command: `HF_TOKEN=${userToken} bun run eval` },
      session_id: "leak",
      call_index: 0,
      ts: "2026-11-22T00:00:00Z",
    };
    const w = new TraceWriter(tracePath);
    w.append(draft);
    w.seal();
    expect(() =>
      buildPacket({ name: "leak", source: "claude-hook", sessionId: "leak", task: "leak test", outRoot: join(dir, "out"), tracePath, signer: { mode: "key", key: join(dir, "no.key"), pub: join(dir, "no.pub"), password: "x", signingConfig: join(dir, "no.json") } }),
    ).toThrow(/refusing to sign leak: COL-10 not-satisfied/);
  }, 30_000);
});

describe("S66 the incident replay in docs/outside-cases.md", () => {
  test("S66 the write is allowed and recorded by path and input hash; the commit and the push are handed to the human; the packet verifies", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-s66-"));
    const { recordPath, pub, key } = signedRecord(dir);
    const traceDir = join(dir, "hook");
    const writeInput = { file_path: "/work/acme-evals/src/eval/loader.ts", content: `export const HF_TOKEN = "${userToken}";\n` };
    const events = [
      event("s66", "Write", writeInput, "t1"),
      event("s66", "Bash", { command: 'git add -A && git commit -m "add eval loader"' }, "t2"),
      event("s66", "Bash", { command: "git push origin main" }, "t3"),
    ];
    const results = events.map((line) => runHook(line, { recordPath, pubkeyPath: pub, traceDir }));
    expect(results.map((r) => r.output.hookSpecificOutput.permissionDecision)).toEqual(["allow", "ask", "ask"]);
    expect(results.map((r) => r.verdict.rule_ids[0])).toEqual(["COL-GATE-ALLOW", "COL-GATE-APPROVAL", "COL-GATE-APPROVAL"]);

    const tracePath = tracePathFor(traceDir, "s66");
    expect(verifyTrace(tracePath)).toMatchObject({ ok: true, lines: 3, sealed: true });
    const t = readTrace(tracePath);
    // The Decision for the write holds where it wrote and a hash of the whole input. It holds none of the content.
    expect(t[0]!.args_redacted).toEqual({ path: "src/eval/loader.ts", data_class: "internal" });
    expect(t[0]!.reasons.find((r) => r.field === "claude.tool_input_sha256")?.value).toBe(canonicalSha256(writeInput));
    expect(JSON.stringify(t[0])).not.toContain("HF_TOKEN");
    expect(t.map((d) => d.effect)).toEqual(["allow", "escalate", "escalate"]);

    const p = sealSession({ sessionId: "s66", traceDir, recordPath, pubkeyPath: pub, outRoot: join(dir, "out"), signer: { mode: "key", key, pub, password: "test", signingConfig: offlineSigningConfig(join(dir, "keys")) } });
    expect(verifyBundle({ dir: p.bundleDir, pubkey: pub }).ok).toBe(true);
    const state = (id: string) => p.results.find((r) => r.control.id === id)?.state;
    expect(state("COL-03")).toBe("not-satisfied"); // no refusal occurred, so the control was not exercised (D12)
    expect(state("COL-10")).toBe("satisfied");
    expect(filesUnder(p.bundleDir).filter((f) => f.text.includes(userToken)).map((f) => f.path)).toEqual([]);
  }, 60_000);
});
