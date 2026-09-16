import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { normalizeAgentcoreDogwood, parseAwsStyleMap, SOURCE } from "../packages/adapters/agentcore-dogwood/index.ts";

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

  test("parses AWS Java-style requestBody maps", () => {
    expect(parseAwsStyleMap("{id=1, jsonrpc=2.0, method=tools/call, params={name=StatusTarget___get_status, arguments={}}}")).toEqual({
      id: "1",
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "StatusTarget___get_status", arguments: {} },
    });
    expect(parseAwsStyleMap("{id=2, jsonrpc=2.0, method=tools/call, params={name=StatusTarget___do_sensitive, arguments={action=exfil}}}")).toEqual({
      id: "2",
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "StatusTarget___do_sensitive", arguments: { action: "exfil" } },
    });
  });

  test("live APPLICATION_LOGS RoE: five decisions joined on request_id; session_id from sidecar", () => {
    const n = normalizeAgentcoreDogwood(join(FIX, "live-roe-7461903f.jsonl"));
    expect(n.sessionId).toBe("7461903f-e0c0-41ce-844b-87d43dcb1a23");
    expect(n.drafts).toHaveLength(5);
    expect(n.drafts.every((d) => d.session_id === "7461903f-e0c0-41ce-844b-87d43dcb1a23")).toBe(true);
    expect(n.drafts.map((d) => `${d.effect}:${d.rule_ids[0]}:${d.tool}`)).toEqual([
      "allow:permit_get_status_scoped-zn8oczkgdi:StatusTarget___get_status",
      "deny:AGENTCORE-DEFAULT-DENY:StatusTarget___do_sensitive",
      "allow:permit_approve_action_scoped-jmopu2crfw:StatusTarget___approve_action",
      "allow:permit_sensitive_after_approval-uvlil0uj9e:StatusTarget___do_sensitive",
      "deny:AGENTCORE-DEFAULT-DENY:StatusTarget___do_sensitive",
    ]);
    expect(n.drafts[0]!.args_redacted).toEqual({});
    expect(n.drafts[1]!.args_redacted).toEqual({ action: "exfil" });
    expect(n.drafts[2]!.args_redacted).toEqual({ action: "exfil" });
    expect(n.drafts[3]!.args_redacted).toEqual({ action: "exfil" });
    expect(n.drafts[4]!.args_redacted).toEqual({ action: "other" });
    expect(n.drafts[1]!.reasons.some((r) => r.field.endsWith("principal.entityId") && String(r.value).includes("roe-operator"))).toBe(true);
    expect(n.drafts[1]!.reasons.some((r) => r.field.endsWith("request_id") && r.value === "c3b0b8bc-fb65-41d4-9a2b-a033ad29fdaf")).toBe(true);
    expect(n.drafts[1]!.reasons.some((r) => r.field.endsWith("temporal_evaluation_invoked") && r.value === true)).toBe(true);
    expect(n.drafts[1]!.reasons.some((r) => /denied by default/.test(String(r.value)))).toBe(true);
    expect(n.task).toMatch(/APPLICATION_LOGS/);
    expect(n.task).toMatch(/Session id is capture metadata/);
    expect(n.evidence.some((e) => e.kind === "agentcore-pep-binding")).toBe(true);
    expect(n.evidence.some((e) => e.kind === "agentcore-capture-metadata")).toBe(true);
    expect(JSON.stringify(n)).not.toMatch(/arn:aws:iam::\d{12}:/);
  });

  test("APPLICATION_LOGS requires session_id from sidecar or --session", () => {
    const dir = mkdtempSync(join(tmpdir(), "colophon-ac-live-"));
    const p = join(dir, "orphan.jsonl");
    writeFileSync(
      p,
      JSON.stringify({
        ts: 1789522888532,
        request_id: "req-orphan",
        log: "Policy evaluation denied request",
        policy: { decision: "DENY", determiningPolicies: [], reason: "No policy applies to the request (denied by default)." },
      }) + "\n",
    );
    expect(() => normalizeAgentcoreDogwood(p)).toThrow(/session_id/);
    const n = normalizeAgentcoreDogwood(p, { sessionId: "from-cli-flag" });
    expect(n.sessionId).toBe("from-cli-flag");
    expect(n.drafts).toHaveLength(1);
    expect(n.drafts[0]!.tool).toBe("unknown-tool");
    expect(n.drafts[0]!.rule_ids).toEqual(["AGENTCORE-DEFAULT-DENY"]);
  });

  test("--session overrides sidecar; Executing-tool lines are not decisions", () => {
    const n = normalizeAgentcoreDogwood(join(FIX, "live-roe-7461903f.jsonl"), { sessionId: "cli-override" });
    expect(n.sessionId).toBe("cli-override");
    expect(n.drafts).toHaveLength(5);
    expect(n.drafts.every((d) => d.session_id === "cli-override")).toBe(true);
  });
});
