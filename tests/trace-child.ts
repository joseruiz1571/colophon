// One "hook process" for the S63 test: open the trace like runHook does, wait for the shared start time, append one Decision.
import { argsSha256, redactArgs } from "../packages/normalize/decision.ts";
import { TraceWriter } from "../packages/trace/trace.ts";

const [tracePath, startAt, idx, recordSha] = process.argv.slice(2) as [string, string, string, string];
const args = { path: `out/evidence-reader/f${idx}.txt`, data_class: "internal" };
const t = new TraceWriter(tracePath);
while (Date.now() < Number(startAt)) {
  // spin: release every child at the same instant
}
t.append({ source: "colophon-gate", effect: "allow", rule_ids: ["COL-GATE-ALLOW"], reasons: [{ field: "tools[].name", value: "fs.write" }], tool: "fs.write", args_sha256: argsSha256(args), args_redacted: redactArgs(args), session_id: "s63", call_index: Number(idx), record_sha256: recordSha, ts: new Date().toISOString() });
