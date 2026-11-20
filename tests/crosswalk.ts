/**
 * S59: docs/proof-of-control.md is checked against the standard it cites.
 *
 *   - every requirement id it cites exists in the vendored checklist, at the
 *     level the checklist gives it;
 *   - every graded row carries a state (met, partly met, not met) and a
 *     pointer: a file that exists in this repository, a section of the
 *     document, a probe id, a control id, or a quoted verifier line;
 *   - the Tier claimed is 2, and no claim in the register is above it;
 *   - at least one requirement is stated as not met.
 *
 * Prints a summary and exits 1 on any failure. It reads; it grades nothing:
 * whether a state is the right state is a judgment this file cannot make.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const DOC = "docs/proof-of-control.md";
const CHECKLIST = "packages/fixtures/proof-of-control/poc-checklist.csv";
const STATES = ["met", "partly met", "not met"] as const;

function parseCsvLine(l: string): string[] {
  const out: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < l.length; i++) {
    const ch = l[i]!;
    if (quoted) {
      if (ch === '"') {
        if (l[i + 1] === '"') {
          cell += '"';
          i++;
        } else quoted = false;
      } else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      out.push(cell);
      cell = "";
    } else cell += ch;
  }
  out.push(cell);
  return out;
}

const failures: string[] = [];
const csv = readFileSync(resolve(ROOT, CHECKLIST), "utf8").trim().split(/\r?\n/);
const header = parseCsvLine(csv[0]!);
const idCol = header.indexOf("id");
const levelCol = header.indexOf("level");
if (idCol < 0 || levelCol < 0) throw new Error(`${CHECKLIST}: no id or level column`);
const levels = new Map<string, string>();
for (const line of csv.slice(1)) {
  const cells = parseCsvLine(line);
  levels.set(cells[idCol]!, cells[levelCol]!);
}

const doc = readFileSync(resolve(ROOT, DOC), "utf8");
const lines = doc.split("\n");

// Graded rows: | 7.1.1 | 3 | state | text |
type Row = { id: string; level: string; state: string; text: string };
const rows: Row[] = [];
for (const l of lines) {
  const m = /^\| (\d+\.\d+\.\d+) \| (\d) \| ([a-z ]+?) \| (.+) \|$/.exec(l);
  if (m) rows.push({ id: m[1]!, level: m[2]!, state: m[3]!, text: m[4]! });
}

const seen = new Set<string>();
let unresolved = 0;
for (const r of rows) {
  if (seen.has(r.id)) failures.push(`${r.id}: graded twice`);
  seen.add(r.id);
  const level = levels.get(r.id);
  if (level === undefined) {
    unresolved++;
    failures.push(`${r.id}: not a requirement in the checklist`);
    continue;
  }
  if (level !== r.level) failures.push(`${r.id}: the document says level ${r.level}, the checklist says ${level}`);
  if (!(STATES as readonly string[]).includes(r.state)) failures.push(`${r.id}: state "${r.state}" is not one of ${STATES.join(", ")}`);

  // A pointer: a backticked token (file, field, verifier line), a section mark, a probe id, or a control id.
  const ticks = [...r.text.matchAll(/`([^`]+)`/g)].map((m) => m[1]!);
  const hasPointer = ticks.length > 0 || /§\d/.test(r.text) || /\bS\d+\b/.test(r.text) || /\bCOL-\d+\b/.test(r.text);
  if (!hasPointer) failures.push(`${r.id}: no file, section, probe, control or verifier line named`);
  for (const t of ticks) {
    const pathLike = /^[\w.\-/]+\.(ts|json|md|rego|yaml|yml|csv)$/.test(t) && (t.includes("/") || /^[A-Z]+\.md$/.test(t));
    if (pathLike && !existsSync(resolve(ROOT, t))) failures.push(`${r.id}: cites ${t}, which does not exist`);
  }
}

// Ids written in prose carry the C prefix (C7.1.1); they must resolve too.
const proseIds = new Set([...doc.matchAll(/\bC(\d+\.\d+\.\d+)\b/g)].map((m) => m[1]!));
for (const id of proseIds) {
  if (!levels.has(id)) {
    unresolved++;
    failures.push(`C${id}: cited in prose, not a requirement in the checklist`);
  }
}

// Tier: the stated claim, and the register's Tier column (last cell of each PC row).
const claimed = /^\*\*Tier claimed:\*\* (\d)$/m.exec(doc)?.[1];
if (claimed !== "2") failures.push(`Tier claimed is ${claimed ?? "not stated"}; S59 requires 2`);
const registerTiers = lines.map((l) => /^\| PC-\d+ \|.*\| (\d) \|$/.exec(l)?.[1]).filter((t): t is string => t !== undefined);
if (registerTiers.length === 0) failures.push("no claim register rows (| PC-n | … | tier |) found");
const maxTier = Math.max(0, ...registerTiers.map(Number));
if (maxTier > 2) failures.push(`a claim in the register is at Tier ${maxTier}, above the Tier claimed`);

const count = (s: string) => rows.filter((r) => r.state === s).length;
if (rows.length < 10) failures.push(`only ${rows.length} requirements graded; S59 requires at least 10`);
if (count("not met") < 1) failures.push("no requirement is stated as not met");

console.log(`cited: ${rows.length}`);
console.log(`unresolved: ${unresolved}`);
console.log(`met: ${count("met")}`);
console.log(`partly-met: ${count("partly met")}`);
console.log(`not-met: ${count("not met")}`);
console.log(`claims: ${registerTiers.length}`);
console.log(`tier: ${claimed ?? "none"}`);
for (const f of failures) console.error(`FAIL ${f}`);
process.exit(failures.length ? 1 : 0);
