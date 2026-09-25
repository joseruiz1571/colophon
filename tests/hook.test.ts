/**
 * Colophon as a Claude Code PreToolUse hook. Mapping is a pure naming
 * contract; the end-to-end tests sign a real Record with a throwaway cosign
 * key and run the events fixture through runHook one call at a time, then
 * seal, exactly as the demo does. cosign and opa must be on the path (they
 * are in CI and for the probes).
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { normalizeClaudeHook } from "../packages/adapters/claude-hook/index.ts";
import { generateKeyPair, offlineSigningConfig, signBlobWithKey } from "../packages/bundle/sign.ts";
import { verifyBundle } from "../packages/bundle/verify.ts";
import { recordSignaturePath } from "../packages/gate/server.ts";
import { declaredToolName, mapCall, portablePath, runHook, sealSession, settingsSnippet, toOutput, tracePathFor } from "../packages/hook/index.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";
import { readTrace, verifyTrace } from "../packages/trace/trace.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");

describe("tool mapping is a naming contract", () => {
  test("built-in tools map to declared names; MCP names lower into the grammar", () => {
    expect(declaredToolName("Read")).toBe("fs.read");
    expect(declaredToolName("Glob")).toBe("fs.read");
    expect(declaredToolName("Grep")).toBe("fs.read");
    expect(declaredToolName("Write")).toBe("fs.write");
    expect(declaredToolName("Edit")).toBe("fs.write");
    expect(declaredToolName("NotebookEdit")).toBe("fs.write");
    expect(declaredToolName("Bash")).toBe("shell.exec");
    expect(declaredToolName("WebFetch")).toBe("net.fetch");
    expect(declaredToolName("WebSearch")).toBe("net.search");
    expect(declaredToolName("mcp__memory__create_entities")).toBe("mcp.memory.create_entities");
    expect(declaredToolName("mcp__plugin_my-plugin_db__Query")).toBe("mcp.plugin_my_plugin_db.query");
    expect(declaredToolName("SomethingNew")).toBe("somethingnew");
    for (const n of ["fs.read", "mcp.memory.create_entities", "somethingnew", "mcp.plugin_my_plugin_db.query"]) expect(n).toMatch(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/);
  });

  test("paths inside cwd become relative; outside or traversing stay absolute", () => {
    expect(portablePath("/work/acme-web", "/work/acme-web/src/index.ts")).toBe("src/index.ts");
    expect(portablePath("/work/acme-web", "src/index.ts")).toBe("src/index.ts");
    expect(portablePath("/work/acme-web", "/etc/cron.d/backdoor")).toBe("/etc/cron.d/backdoor");
    expect(portablePath("/work/acme-web", "/work/acme-web/src/../../etc/passwd")).toBe("/work/etc/passwd");
    expect(portablePath("/work/acme-web", "/work/acme-web-evil/x")).toBe("/work/acme-web-evil/x");
    expect(portablePath("/work/acme-web", "/work/acme-web")).toBe(".");
    expect(portablePath(undefined, "/abs/x")).toBe("/abs/x");
  });

  test("defaults.data_class applies only when absent, and is recorded as context", () => {
    const e = { session_id: "s", cwd: "/w", hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "/w/src/a.ts", content: "x" } };
    const m = mapCall(e, { data_class: "internal" });
    expect(m.name).toBe("fs.write");
    expect(m.arguments).toEqual({ path: "src/a.ts", data_class: "internal" });
    expect(m.context.some((r) => r.field === "defaults.data_class" && r.role === "context")).toBe(true);
    expect(m.context.some((r) => r.field === "claude.tool_name" && r.value === "Write")).toBe(true);
    expect(m.context.some((r) => r.field === "claude.tool_input_sha256")).toBe(true);
    const own = mapCall({ ...e, tool_name: "mcp__x__y", tool_input: { data_class: "public", q: 1 } }, { data_class: "internal" });
    expect(own.arguments["data_class"]).toBe("public");
    expect(own.context.some((r) => r.field === "defaults.data_class")).toBe(false);
    expect(mapCall({ ...e, tool_name: "Bash", tool_input: { command: "ls" } }, undefined).arguments).toEqual({ command: "ls" });
    expect(mapCall({ ...e, tool_name: "WebFetch", tool_input: { url: "https://x.example", prompt: "p" } }, undefined).arguments).toEqual({ url: "https://x.example" });
  });

  test("output shape and reason text are replayable by the claude-hook adapter", () => {
    const o = toOutput({ effect: "deny", rule_ids: ["COL-GATE-SANDBOX", "COL-GATE-DATACLASS"], reasons: [{ field: "sandbox.write_paths", value: "/etc/x" }] });
    expect(o.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(o.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(o.hookSpecificOutput.permissionDecisionReason).toBe('[COL-GATE-SANDBOX] sandbox.write_paths: "/etc/x" (also COL-GATE-DATACLASS)');
    expect(toOutput({ effect: "escalate", rule_ids: ["COL-GATE-APPROVAL"], reasons: [{ field: "tools[].requires_approval", value: "shell.exec" }] }).hookSpecificOutput.permissionDecision).toBe("ask");
  });
});

function signedRecord(dir: string): { recordPath: string; pub: string; key: string } {
  const keys = generateKeyPair(join(dir, "keys"), "test");
  const decl = loadDeclaration(join(FIX, "declarations", "claude-coder.yaml"));
  const record = buildRecord(decl);
  const recordPath = join(dir, "claude-coder.record.json");
  writeFileSync(recordPath, JSON.stringify(record, null, 2) + "\n");
  signBlobWithKey({ blob: recordPath, key: keys.key, password: "test", out: recordSignaturePath(recordPath), signingConfig: offlineSigningConfig(join(dir, "keys")) });
  return { recordPath, pub: keys.pub, key: keys.key };
}

describe("hook end to end", () => {
  const dir = mkdtempSync(join(tmpdir(), "colophon-hook-"));
  const { recordPath, pub, key } = signedRecord(dir);
  const traceDir = join(dir, "hook");
  const events = readFileSync(join(FIX, "claude-hook", "events.jsonl"), "utf8").split("\n").filter(Boolean);

  test("eight events: allow, allow, allow, ask, deny×4 with the expected rule ids; chain intact; self-test written", () => {
    const decisions = events.map((line) => runHook(line, { recordPath, pubkeyPath: pub, traceDir }));
    expect(decisions.map((d) => d.output.hookSpecificOutput.permissionDecision)).toEqual(["allow", "allow", "allow", "ask", "deny", "deny", "deny", "deny"]);
    expect(decisions.map((d) => d.verdict.rule_ids[0])).toEqual([
      "COL-GATE-ALLOW",
      "COL-GATE-ALLOW",
      "COL-GATE-ALLOW",
      "COL-GATE-APPROVAL",
      "COL-GATE-SANDBOX",
      "COL-GATE-DESTINATION",
      "COL-GATE-SANDBOX",
      "COL-GATE-UNKNOWN-TOOL",
    ]);
    const tracePath = tracePathFor(traceDir, "cc-live-0001");
    expect(verifyTrace(tracePath)).toMatchObject({ ok: true, lines: 8, sealed: true });
    const t = readTrace(tracePath);
    expect(t.map((d) => d.tool)).toEqual(["fs.read", "fs.write", "fs.write", "shell.exec", "fs.write", "net.fetch", "fs.write", "mcp.memory.search"]);
    expect(t[4]!.args_redacted).toEqual({ path: "/etc/cron.d/backdoor", data_class: "internal" });
    expect(t[6]!.args_redacted).toEqual({ path: ".env", data_class: "internal" });
    expect(t.every((d) => d.source === "colophon-hook" && d.record_sha256)).toBe(true);
    expect(existsSync(join(traceDir, "cc-live-0001.selftest.json"))).toBe(true);
    // Replaying the hook's own log through the fixture adapter recovers the same effects and first rule ids (H5).
    const log = join(dir, "replay.jsonl");
    writeFileSync(log, events.map((line, i) => JSON.stringify({ ...(JSON.parse(line) as object), hook_response: decisions[i]!.output })).join("\n") + "\n");
    const n = normalizeClaudeHook(log);
    expect(n.drafts.map((d) => d.effect)).toEqual(t.map((d) => d.effect));
    expect(n.drafts.map((d) => d.rule_ids[0])).toEqual(t.map((d) => d.rule_ids[0]));
  });

  test("fail closed: malformed stdin, unverifiable Record, OPA failure", () => {
    const bad = runHook("not json", { recordPath, pubkeyPath: pub, traceDir });
    expect(bad.output.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(bad.output.hookSpecificOutput.permissionDecisionReason).toMatch(/^\[COL-GATE-OPA-ERROR\]/);
    expect(bad.sessionId).toBeNull();

    const line = events[0]!;
    const unsigned = join(dir, "unsigned.record.json");
    writeFileSync(unsigned, readFileSync(recordPath));
    const noSig = runHook(line, { recordPath: unsigned, pubkeyPath: pub, traceDir: join(dir, "hook-nosig") });
    expect(noSig.output.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(noSig.output.hookSpecificOutput.permissionDecisionReason).toMatch(/signature file missing/);
    expect(readTrace(tracePathFor(join(dir, "hook-nosig"), "cc-live-0001"))).toHaveLength(1);

    const opa = runHook(line, { recordPath, pubkeyPath: pub, traceDir: join(dir, "hook-opa"), policyPath: "/nonexistent/gate.rego" });
    expect(opa.output.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(opa.verdict.rule_ids).toEqual(["COL-GATE-OPA-ERROR"]);
    const t = readTrace(tracePathFor(join(dir, "hook-opa"), "cc-live-0001"));
    expect(t[0]!.effect).toBe("deny");
    expect(t[0]!.rule_ids).toEqual(["COL-GATE-OPA-ERROR"]);
  });

  test("seal: verified packet, 9/9 controls including the policy binding, SIGNATURE only after verify", () => {
    const p = sealSession({ sessionId: "cc-live-0001", traceDir, recordPath, pubkeyPath: pub, outRoot: join(dir, "out"), signer: { mode: "key", key, pub, password: "test", signingConfig: offlineSigningConfig(join(dir, "keys")) } });
    expect(p.source).toBe("colophon-hook");
    expect(p.results.every((r) => r.state === "satisfied")).toBe(true);
    expect(p.results).toHaveLength(9);
    expect(p.decisions.every((d) => typeof d.policy_sha256 === "string")).toBe(true);
    expect(existsSync(join(p.bundleDir, "policy", "gate.rego"))).toBe(true);
    expect(existsSync(p.signaturePath)).toBe(true);
    expect(verifyBundle({ dir: p.bundleDir, pubkey: pub }).ok).toBe(true);
    const narrative = readFileSync(join(p.bundleDir, "report", "narrative.md"), "utf8");
    expect(narrative).toMatch(/PreToolUse hook/);
    expect(narrative).toMatch(/COL-05 .*\*\*satisfied\*\*/);
    expect(narrative).not.toMatch(/not a re-run of the foreign policy set/);
    expect(() => sealSession({ sessionId: "nope", traceDir, recordPath, pubkeyPath: pub, outRoot: join(dir, "out2"), signer: { mode: "key", key, pub, password: "test", signingConfig: offlineSigningConfig(join(dir, "keys")) } })).toThrow(/no trace for session/);
  });

  test("settings snippet is the documented hooks shape", () => {
    const s = settingsSnippet({ cli: "packages/cli/main.ts", recordPath, pubkeyPath: pub, traceDir }) as { hooks: { PreToolUse: { matcher: string; hooks: { type: string; command: string; timeout: number }[] }[] } };
    expect(s.hooks.PreToolUse[0]!.matcher).toBe("");
    expect(s.hooks.PreToolUse[0]!.hooks[0]!.type).toBe("command");
    expect(s.hooks.PreToolUse[0]!.hooks[0]!.timeout).toBe(30);
    expect(s.hooks.PreToolUse[0]!.hooks[0]!.command).toMatch(/^bun \/.*main\.ts hook --record \/.* --pubkey \/.* --trace-dir \//);
  });
});
