/**
 * S9: one line of gate.rego changes a demo decision; no .ts file changes.
 * Copies the policy, edits the sandbox rule so any traversal-free path counts
 * as inside the sandbox, reruns the evidence-reader scenario with the copy,
 * and reports the flip. Needs a prior `bun run demo` (records + keys).
 */
import { copyFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { loadScenario, runScenario } from "../packages/gate/agent.ts";
import { readTrace } from "../packages/trace/trace.ts";
import { GATE_POLICY } from "../packages/policy/opa.ts";
import { listFiles } from "../packages/bundle/manifest.ts";

const ROOT = resolve(import.meta.dir, "..");
const OUT = process.env["OUT"] ?? join(ROOT, "out", "demo");
const record = join(OUT, "records", "evidence-reader.record.json");
const pub = join(OUT, "keys", "cosign.pub");
if (!existsSync(record) || !existsSync(pub)) {
  console.error("run `bun run demo` first");
  process.exit(1);
}
const tsHash = () => createHash("sha256").update(listFiles(join(ROOT, "packages")).filter((p) => p.endsWith(".ts")).map((p) => p + ":" + createHash("sha256").update(readFileSync(join(ROOT, "packages", p))).digest("hex")).join("\n")).digest("hex");
const before = tsHash();

const tmp = mkdtempSync(join(tmpdir(), "colophon-flip-"));
const policy = join(tmp, "gate.rego");
copyFileSync(GATE_POLICY, policy);
const original = readFileSync(policy, "utf8");
const edited = original.replace("\tstartswith(p, prefix)\n", "\ttrue # FLIP: every traversal-free path is treated as inside the sandbox\n");
if (edited === original) throw new Error("policy line to edit not found");
writeFileSync(policy, edited);

const scenario = loadScenario(join(ROOT, "packages/fixtures/scenarios/evidence-reader.yaml"));
const run = async (env: Record<string, string>, name: string) => {
  const dir = join(tmp, name);
  await runScenario({ scenario, recordPath: record, pubkeyPath: pub, tracePath: join(dir, "trace.jsonl"), sessionId: name, upstream: [process.execPath, join(ROOT, "packages/cli/main.ts"), "upstream", "demo"], upstreamLog: join(dir, "upstream.jsonl"), selfTestOut: join(dir, "selftest.json"), env });
  return readTrace(join(dir, "trace.jsonl"));
};
const base = await run({}, "base");
const flipped = await run({ COLOPHON_GATE_POLICY: policy }, "flipped");
const idx = scenario.calls.findIndex((c) => c.tool === "fs.write" && c.arguments["path"] === "/tmp/gh-token.json");
const b = base[idx]!;
const f = flipped[idx]!;
console.log(`base:    fs.write /tmp/gh-token.json → ${b.effect} [${b.rule_ids.join(",")}]`);
console.log(`flipped: fs.write /tmp/gh-token.json → ${f.effect} [${f.rule_ids.join(",")}]`);
const after = tsHash();
console.log(`ts-diff: ${before === after ? 0 : 1}`);
if (b.effect === "deny" && b.rule_ids.includes("COL-GATE-SANDBOX") && f.effect === "allow" && before === after) {
  console.log("FLIP: sandbox-escape deny -> allow");
  process.exit(0);
}
console.log("no flip");
process.exit(1);
