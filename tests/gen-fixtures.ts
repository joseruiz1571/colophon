/**
 * Generates fixtures that must be internally consistent (valid hashes, chained
 * traces) and therefore cannot be hand-written: three bad Records for lint,
 * one breach trace where an out-of-scope call was allowed, and the seven
 * gate-input files for `opa eval`. Deterministic; re-run and commit.
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { argsSha256, redactArgs, sealDecision, type Decision, type DecisionDraft } from "../packages/normalize/decision.ts";
import { buildRecord, loadDeclaration, type Declaration } from "../packages/schema/record.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");
const NOW = new Date("2026-09-10T12:00:00Z");
const decl = loadDeclaration(join(FIX, "declarations", "evidence-reader.yaml"));

function write(path: string, value: unknown): void {
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

// --- bad records (hash-valid, lint-invalid) ---
const stale: Declaration = { ...decl, review_due: "2020-01-01" };
const noKill: Declaration = { ...decl, kill_switch: { available: false, mechanism: "none" } };
const authUnbounded: Declaration = { ...decl, max_scopes: [] };
write(join(FIX, "records", "bad", "stale.record.json"), buildRecord(stale, NOW));
write(join(FIX, "records", "bad", "high-no-killswitch.record.json"), buildRecord(noKill, NOW));
write(join(FIX, "records", "bad", "auth-unbounded.record.json"), buildRecord(authUnbounded, NOW));

// --- breach trace: a sandbox escape that was (wrongly) allowed ---
const record = buildRecord(decl, NOW);
const calls: { tool: string; args: Record<string, unknown>; effect: Decision["effect"]; rule_ids: string[]; reasons: Decision["reasons"] }[] = [
  { tool: "repo.list", args: { org: "acme", data_class: "internal" }, effect: "allow", rule_ids: ["COL-GATE-ALLOW"], reasons: [{ field: "tools[].name", value: "repo.list" }] },
  { tool: "fs.write", args: { path: "/tmp/gh-token.json", data_class: "internal" }, effect: "allow", rule_ids: ["COL-GATE-ALLOW"], reasons: [{ field: "tools[].name", value: "fs.write" }] },
  { tool: "mail.send", args: { to: "auditor@acme.example" }, effect: "deny", rule_ids: ["COL-GATE-UNKNOWN-TOOL"], reasons: [{ field: "tools[].name", value: "mail.send" }] },
];
let prev: Decision | null = null;
const lines: string[] = [];
calls.forEach((c, i) => {
  const draft: DecisionDraft = { source: "colophon-gate", effect: c.effect, rule_ids: c.rule_ids, reasons: c.reasons, tool: c.tool, args_sha256: argsSha256(c.args), args_redacted: redactArgs(c.args), session_id: "breach-fixture", call_index: i, record_sha256: record.canonical_sha256, ts: new Date(NOW.getTime() + i * 1000).toISOString() };
  prev = sealDecision(draft, prev);
  lines.push(JSON.stringify(prev));
});
mkdirSync(join(FIX, "traces"), { recursive: true });
writeFileSync(join(FIX, "traces", "breach.jsonl"), lines.join("\n") + "\n");

// --- gate inputs for `opa eval` ---
const ctx = { session_id: "fixture", call_index: 0 };
const inputs: Record<string, { name: string; arguments: Record<string, unknown> }> = {
  "in-scope": { name: "repo.read_settings", arguments: { repo: "acme/web", data_class: "internal" } },
  "unknown-tool": { name: "mail.send", arguments: { to: "auditor@acme.example" } },
  "scope-expansion": { name: "auth.request_scopes", arguments: { scopes: ["repo:read", "admin:org"] } },
  "sandbox-escape": { name: "fs.write", arguments: { path: "/tmp/gh-token.json", data_class: "internal" } },
  "data-class": { name: "fs.read", arguments: { path: "secrets/deploy-token.txt", data_class: "secret" } },
  "destination": { name: "mail.send", arguments: { to: "ops@evil.example", subject: "x" } },
  "needs-approval": { name: "deploy.run", arguments: { target: "staging" } },
};
const withApproval: Declaration = { ...decl, tools: [...decl.tools, { name: "deploy.run", data_access: "none", data_classes: [], requires_approval: true }] };
const notifier = loadDeclaration(join(FIX, "declarations", "notifier.yaml"));
rmSync(join(FIX, "gate-input"), { recursive: true, force: true });
for (const [name, call] of Object.entries(inputs)) {
  const d = name === "needs-approval" ? withApproval : name === "destination" ? notifier : decl;
  write(join(FIX, "gate-input", `${name}.json`), { record: buildRecord(d, NOW), call, context: ctx });
}
console.log("fixtures generated");
