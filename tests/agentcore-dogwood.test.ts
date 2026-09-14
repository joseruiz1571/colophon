import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { normalizeAgentcoreDogwood, SOURCE } from "../packages/adapters/agentcore-dogwood/index.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures/agentcore-dogwood");

describe("agentcore-dogwood adapter", () => {
  test("RoE fixture: allow, approve-before-act deny then allow, out-of-scope deny, rate-limit deny", () => {
    const n = normalizeAgentcoreDogwood(join(FIX, "session.jsonl"));
    expect(n.sessionId).toBe("ac-roe-0001");
    expect(SOURCE).toBe("agentcore-dogwood");
    expect(n.drafts.map((d) => `${d.effect}:${d.rule_ids[0]}:${d.tool}`)).toEqual([
      "allow:DW-PERMIT-IN-SCOPE-READ:repo.read_file",
      "deny:DW-APPROVE-BEFORE-ACT:repo.git_push",
      "allow:DW-PERMIT-APPROVAL:approvals.approve",
      "allow:DW-APPROVE-BEFORE-ACT:repo.git_push",
      "deny:DW-OUT-OF-SCOPE:shell.run",
      "allow:DW-PERMIT-IN-SCOPE-SHELL:shell.run",
      "deny:DW-RATE-LIMIT:shell.run",
    ]);
    expect(n.drafts.every((d) => d.source === SOURCE)).toBe(true);
    expect(n.drafts.every((d) => d.session_id === "ac-roe-0001")).toBe(true);
    expect(n.drafts.every((d) => /^[0-9a-f]{64}$/.test(d.args_sha256))).toBe(true);
    expect(n.evidence.some((e) => e.kind === "agentcore-pep-binding")).toBe(true);
    expect(n.task).toMatch(/Signed artifact for agent rules of engagement/);
    expect(n.task).toMatch(/Coding-agent evidence of controls/);
  });

  test("missing or unknown decision is deny fail-closed", () => {
    const n = normalizeAgentcoreDogwood(join(FIX, "no-decision.jsonl"));
    expect(n.drafts).toHaveLength(2);
    expect(n.drafts[0]!.effect).toBe("deny");
    expect(n.drafts[0]!.rule_ids).toEqual(["AGENTCORE-NO-DECISION"]);
    expect(n.drafts[1]!.effect).toBe("deny");
    expect(n.drafts[1]!.rule_ids).toEqual(["AGENTCORE-NO-DECISION"]);
  });

  test("history-only events produce no decision; LOG_ONLY is recorded not rewritten", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-ac-"));
    const p = join(dir, "mixed.jsonl");
    writeFileSync(
      p,
      [
        JSON.stringify({
          event_kind: "AuthorizeAction",
          ts: "2026-09-14T17:00:00Z",
          policy_session_id: "ac-log",
          tool: "repo.read_file",
          input: { path: "a.ts", data_class: "public" },
          authorization_decision: "DENY",
          determining_policies: ["DW-OUT-OF-SCOPE"],
          enforcement_mode: "LOG_ONLY",
          authorization_reason: "would deny",
        }),
        JSON.stringify({
          event_kind: "response",
          history_only: true,
          ts: "2026-09-14T17:00:01Z",
          policy_session_id: "ac-log",
          tool: "repo.read_file",
          authorization_decision: "ALLOW",
        }),
      ].join("\n") + "\n",
    );
    const n = normalizeAgentcoreDogwood(p);
    expect(n.drafts).toHaveLength(1);
    expect(n.drafts[0]!.effect).toBe("deny");
    expect(n.drafts[0]!.reasons.some((r) => r.field.includes("policy.mode") && r.value === "LOG_ONLY")).toBe(true);
  });

  test("JSON array and envelope parse; replay-only report is rejected", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-ac-"));
    const arr = join(dir, "arr.json");
    writeFileSync(
      arr,
      JSON.stringify([
        {
          ts: "2026-09-14T18:00:00Z",
          policy_session_id: "ac-arr",
          tool: "repo.read_file",
          input: { path: "x", data_class: "public" },
          authorization_decision: "allow",
        },
      ]),
    );
    expect(normalizeAgentcoreDogwood(arr).drafts[0]!.effect).toBe("allow");
    const env = join(dir, "env.json");
    writeFileSync(
      env,
      JSON.stringify({
        policy_session_id: "ac-env",
        task: "envelope task",
        events: [{ ts: "2026-09-14T18:00:01Z", tool: "shell.run", input: { command: "true" }, authorization_decision: "DENY" }],
      }),
    );
    const e = normalizeAgentcoreDogwood(env);
    expect(e.sessionId).toBe("ac-env");
    expect(e.task).toBe("envelope task");
    expect(e.drafts[0]!.rule_ids).toEqual(["AGENTCORE-IMPLICIT-DENY"]);
    const replay = join(dir, "replay.json");
    writeFileSync(replay, JSON.stringify({ verdicts: [{ index: 0, timestamp: 0, verdict: "allow", determining_rules: [], errors: [] }] }));
    expect(() => normalizeAgentcoreDogwood(replay)).toThrow(/verdicts/);
  });

  test("secret-named args are redacted", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-ac-"));
    const p = join(dir, "secret.jsonl");
    writeFileSync(
      p,
      JSON.stringify({
        ts: "2026-09-14T19:00:00Z",
        policy_session_id: "ac-secret",
        tool: "repo.read_file",
        input: { path: "x", data_class: "public", token: "not-a-real-secret" },
        authorization_decision: "ALLOW",
      }) + "\n",
    );
    const d = normalizeAgentcoreDogwood(p).drafts[0]!;
    expect(String(d.args_redacted!["token"])).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(d)).not.toContain("not-a-real-secret");
  });
});
