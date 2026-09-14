import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { loadRecord, type ColophonRecord } from "../../schema/record.ts";
import { readTrace, verifyTrace } from "../../trace/trace.ts";
import { buildFindings, type FindingDocument } from "./map.ts";

function listJsonl(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => n.endsWith(".jsonl") && !n.endsWith(".head.json"))
    .map((n) => join(dir, n))
    .sort();
}

export function discoverTracePaths(from: string): string[] {
  const found = [
    ...listJsonl(join(from, "trace")),
    ...listJsonl(join(from, "bundle", "trace")),
    ...listJsonl(join(from, "stage", "trace")),
    ...listJsonl(from),
  ];
  return [...new Set(found)];
}

function loadSessionMeta(from: string): { source?: string; session_id?: string; task?: string; record?: string | null } | null {
  for (const p of [join(from, "session.json"), join(from, "bundle", "session.json"), join(from, "stage", "session.json")]) {
    if (!existsSync(p)) continue;
    return JSON.parse(readFileSync(p, "utf8")) as { source?: string; session_id?: string; task?: string; record?: string | null };
  }
  return null;
}

function loadBoundRecord(from: string, named?: string | null): ColophonRecord | null {
  const dirs = [join(from, "records"), join(from, "bundle", "records"), join(from, "stage", "records")];
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    const names = readdirSync(dir).filter((n) => n.endsWith(".record.json")).sort();
    const pick = named ? names.find((n) => n === named) ?? names[0] : names[0];
    if (!pick) continue;
    return loadRecord(join(dir, pick));
  }
  return null;
}

export type ExportFromDirOptions = { from: string; source?: string; record?: ColophonRecord | null };

export function findingsFromDir(o: ExportFromDirOptions): FindingDocument[] {
  const traces = discoverTracePaths(o.from);
  if (traces.length === 0) throw new Error(`${o.from}: no sealed Decision traces found (looked in trace/, bundle/trace/, stage/trace/)`);
  const session = loadSessionMeta(o.from);
  const record = o.record !== undefined ? o.record : loadBoundRecord(o.from, session?.record);
  const out: FindingDocument[] = [];
  for (const tracePath of traces) {
    const v = verifyTrace(tracePath);
    if (!v.ok) throw new Error(`${tracePath}: refusing to export an unverified trace (${v.reason})`);
    if (!v.sealed) throw new Error(`${tracePath}: refusing to export an unsealed trace`);
    const decisions = readTrace(tracePath);
    const sessionId = session?.session_id ?? decisions[0]?.session_id ?? basename(tracePath, ".jsonl");
    const source = o.source ?? session?.source ?? decisions[0]?.source ?? "colophon";
    out.push(...buildFindings({ decisions, sessionId, source, record, task: session?.task }));
  }
  return out;
}
