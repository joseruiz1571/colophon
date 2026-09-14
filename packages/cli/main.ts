#!/usr/bin/env bun
/**
 * colophon CLI. Every command exits 1 on failure with the error on stderr.
 */
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { normalizeAgentcoreDogwood } from "../adapters/agentcore-dogwood/index.ts";
import { FixtureAwsConfigProvider, normalizeAwsConfig } from "../adapters/aws-config/index.ts";
import { normalizeClaudeHook } from "../adapters/claude-hook/index.ts";
import { createBundle } from "../bundle/manifest.ts";
import { offlineSigningConfig, signBlobKeyless, signBlobWithKey, verifyBlob } from "../bundle/sign.ts";
import { verifyBundle } from "../bundle/verify.ts";
import { loadScenario, runScenario } from "../gate/agent.ts";
import { bindRecord, lintRecord, recordSignaturePath, runGate } from "../gate/server.ts";
import { serveUpstream } from "../gate/upstream.ts";
import { findingsFromDir, validateFinding, writeFindings, buildFindings } from "../export/finding/index.ts";
import { oscalVersionOf, validateOscal } from "../report/oscal.ts";
import { buildRecord, loadDeclaration, loadRecord, verifyRecordHashes } from "../schema/record.ts";
import { formatErrors, validateDeclaration } from "../schema/validate.ts";
import { TraceWriter, readTrace, verifyTrace } from "../trace/trace.ts";
import YAML from "yaml";
import { runDemo } from "./demo.ts";
import { assessToDir } from "./packet.ts";

type Args = { positional: string[]; flags: Record<string, string | true>; rest: string[] };

function parse(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  let rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--upstream") {
      rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else flags[key] = true;
    } else positional.push(a);
  }
  return { positional, flags, rest };
}

function str(flags: Args["flags"], key: string, required = true): string {
  const v = flags[key];
  if (typeof v === "string") return v;
  if (required) throw new Error(`missing --${key}`);
  return "";
}

function out(line: string): void {
  process.stdout.write(line + "\n");
}

function fail(msg: string, code = 1): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

const USAGE = `colophon — signed session packets for AI agent tool use

  declare validate <file>
  record build <declaration> --out <dir>
  record sign <record> --key <cosign.key> [--password <pw>]
  record verify <record> --pubkey <cosign.pub> | --hash-only
  record lint <record>
  gate serve --record <r> --pubkey <pub> --trace <file> --session <id> [--self-test] --upstream <cmd...>
  upstream demo
  agent run --scenario <yaml> --record <r> --pubkey <pub> --out <dir> [--list-tools]
  trace verify <file>
  normalize <claude-hook|aws-config|agentcore-dogwood> <path> --out <dir>
  report --trace <file> --record <r> --out <dir>
  report validate <assessment-results.json>
  export finding --trace <file> --out <dir> [--record <r>] [--source <pep>] [--session <id>]
  export finding --from <dir> --out <dir> [--source <pep>]
  export finding validate <file>
  bundle create --from <stage> --out <dir>
  bundle sign <dir> --key <cosign.key> [--password <pw>] | --keyless
  bundle verify <dir> (--pubkey <pub> | --certificate-identity-regexp <re> --oidc-issuer <url>) [--out <dir>]
  demo [--out out/demo] [--keyless]
`;

async function main(argv: string[]): Promise<number> {
  const { positional, flags, rest } = parse(argv);
  const [cmd, sub, ...more] = positional;

  if (!cmd || cmd === "help" || flags["help"]) {
    out(USAGE);
    return 0;
  }

  if (cmd === "declare" && sub === "validate") {
    const file = more[0] ?? fail("declare validate <file>");
    const text = readFileSync(file, "utf8");
    const parsed: unknown = file.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
    const r = validateDeclaration(parsed);
    if (!r.ok) fail(`${file}: declaration invalid: ${formatErrors(r)}`);
    out(`${file}: valid declaration (${(parsed as { name: string }).name})`);
    return 0;
  }

  if (cmd === "record" && sub === "build") {
    const decl = loadDeclaration(more[0] ?? fail("record build <declaration> --out <dir>"));
    const dir = str(flags, "out");
    mkdirSync(dir, { recursive: true });
    const record = buildRecord(decl);
    const path = join(dir, `${decl.name}.record.json`);
    await Bun.write(path, JSON.stringify(record, null, 2) + "\n");
    out(`${path}: canonical_sha256 ${record.canonical_sha256}`);
    return 0;
  }

  if (cmd === "record" && sub === "sign") {
    const path = more[0] ?? fail("record sign <record> --key <key>");
    const sig = recordSignaturePath(path);
    if (flags["keyless"]) signBlobKeyless({ blob: path, out: sig });
    else {
      const key = str(flags, "key");
      const keyDir = resolve(key, "..");
      signBlobWithKey({ blob: path, key, password: str(flags, "password", false), out: sig, signingConfig: offlineSigningConfig(keyDir) });
    }
    out(`${sig}: written`);
    return 0;
  }

  if (cmd === "record" && sub === "verify") {
    const path = more[0] ?? fail("record verify <record>");
    const record = loadRecord(path);
    const problem = verifyRecordHashes(record);
    if (problem) fail(`${path}: ${problem}`);
    const pub = str(flags, "pubkey", false);
    if (pub) {
      const sig = recordSignaturePath(path);
      verifyBlob({ blob: path, bundle: sig, pubkey: pub });
      out(`${path}: hashes ok; signature ok (${basename(sig)} with ${pub})`);
      return 0;
    }
    if (flags["hash-only"] === true) {
      out(`${path}: hashes ok (--hash-only: signature NOT checked)`);
      return 0;
    }
    fail(`${path}: hashes ok, but no --pubkey given and --hash-only not set; refusing to report an unverified record as ok`);
  }

  if (cmd === "record" && sub === "lint") {
    const path = more[0] ?? fail("record lint <record>");
    const record = loadRecord(path);
    const problem = verifyRecordHashes(record);
    if (problem) fail(`${path}: ${problem}`);
    const r = lintRecord(record);
    if (!r.ok) fail(`${path}: lint failed: ${r.denies.map((d) => `${d.rule_id} (${d.field}): ${d.msg}`).join("; ")}`);
    out(`${path}: lint ok`);
    return 0;
  }

  if (cmd === "gate" && sub === "serve") {
    const selfTestOnly = flags["self-test"] === true;
    await runGate({
      recordPath: str(flags, "record"),
      pubkeyPath: str(flags, "pubkey", false),
      upstream: rest,
      tracePath: str(flags, "trace", !selfTestOnly) || join("out", "gate-selftest.jsonl"),
      sessionId: str(flags, "session", false) || `gate-${Date.now()}`,
      selfTestOnly,
      selfTestOut: str(flags, "self-test-out", false) || undefined,
    });
    return 0;
  }

  if (cmd === "upstream" && sub === "demo") {
    await serveUpstream();
    return 0;
  }

  if (cmd === "agent" && sub === "run") {
    const scenario = loadScenario(str(flags, "scenario"));
    const dir = str(flags, "out");
    const sessionId = `${scenario.name}-${Date.now()}`;
    const tracePath = join(dir, "trace", `${sessionId}.jsonl`);
    rmSync(join(dir, "trace"), { recursive: true, force: true });
    rmSync(join(dir, "upstream-calls.jsonl"), { force: true });
    const r = await runScenario({
      scenario,
      recordPath: str(flags, "record"),
      pubkeyPath: str(flags, "pubkey", false),
      tracePath,
      sessionId,
      upstream: [process.execPath, resolve(import.meta.dir, "main.ts"), "upstream", "demo"],
      upstreamLog: join(dir, "upstream-calls.jsonl"),
      selfTestOut: join(dir, "selftest.json"),
      listTools: flags["list-tools"] === true,
    });
    for (const o of r.outcomes) out(`${o.refused ? "REFUSED" : "ok     "} ${o.tool}`);
    out(`trace: ${tracePath}`);
    return 0;
  }

  if (cmd === "trace" && sub === "verify") {
    const path = more[0] ?? fail("trace verify <file>");
    const v = verifyTrace(path);
    if (!v.ok) fail(`${path}: chain broken at ${v.reason}`);
    out(`${path}: ${v.lines} decisions; schema: ok; chain: ok; sealed: ${v.sealed ? "yes" : "no"}`);
    return 0;
  }

  if (cmd === "normalize") {
    const adapter = sub ?? fail("normalize <adapter> <path> --out <dir>");
    const src = more[0] ?? fail("normalize <adapter> <path> --out <dir>");
    const dir = str(flags, "out");
    if (adapter === "claude-hook") {
      const n = normalizeClaudeHook(src);
      const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
      rmSync(tracePath, { force: true });
      const w = new TraceWriter(tracePath);
      for (const d of n.drafts) w.append(d);
    w.seal();
      out(`${tracePath}: ${n.drafts.length} decisions from ${src} (source claude-hook)`);
      return 0;
    }
    if (adapter === "aws-config") {
      const n = await normalizeAwsConfig(new FixtureAwsConfigProvider(src));
      const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
      rmSync(tracePath, { force: true });
      const w = new TraceWriter(tracePath);
      for (const d of n.drafts) w.append(d);
    w.seal();
      mkdirSync(join(dir, "evidence-raw"), { recursive: true });
      for (const [i, e] of n.evidence.entries()) await Bun.write(join(dir, "evidence-raw", `${i}-${e.kind}.json`), JSON.stringify(e.payload, null, 2) + "\n");
      out(`${tracePath}: ${n.drafts.length} decisions, ${n.evidence.length} evidence items from ${src} (source aws-config, fixture only)`);
      return 0;
    }
    if (adapter === "agentcore-dogwood") {
      const n = normalizeAgentcoreDogwood(src);
      const tracePath = join(dir, "trace", `${n.sessionId}.jsonl`);
      rmSync(tracePath, { force: true });
      const w = new TraceWriter(tracePath);
      for (const d of n.drafts) w.append(d);
      w.seal();
      mkdirSync(join(dir, "evidence-raw"), { recursive: true });
      for (const [i, e] of n.evidence.entries()) await Bun.write(join(dir, "evidence-raw", `${i}-${e.kind}.json`), JSON.stringify(e.payload, null, 2) + "\n");
      out(`${tracePath}: ${n.drafts.length} decisions, ${n.evidence.length} evidence items from ${src} (source agentcore-dogwood, fixture only)`);
      return 0;
    }
    fail(`unknown adapter ${adapter}`);
  }

  if (cmd === "report" && sub === "validate") {
    const path = more[0] ?? fail("report validate <file>");
    const doc = JSON.parse(readFileSync(path, "utf8"));
    const v = validateOscal(doc);
    if (!v.ok) fail(`${path}: OSCAL invalid: ${v.errors.join("; ")}`);
    out(`${path}: valid OSCAL assessment-results; oscal-version: ${oscalVersionOf(doc)}`);
    return 0;
  }

  if (cmd === "report") {
    const tracePath = str(flags, "trace");
    const recordPath = str(flags, "record");
    const dir = str(flags, "out");
    const record = loadRecord(recordPath);
    const problem = verifyRecordHashes(record);
    if (problem) fail(`${recordPath}: ${problem}`);
    rmSync(dir, { recursive: true, force: true });
    const sig = recordSignaturePath(recordPath);
    if (!existsSync(sig)) fail(`${sig}: record signature missing; a report needs a signed Record`);
    const r = assessToDir({ source: "colophon-gate", sessionId: basename(tracePath, ".jsonl"), task: `Assessment of trace ${tracePath} against Record ${record.declaration.name}`, tracePath, record: { path: recordPath, sigPath: sig, record }, out: dir, verifyCommand: "(assess-only output; no bundle, no signature)" });
    for (const c of r.results) out(`${c.control.id} ${c.state}: ${c.rationale}`);
    out(`report: ${join(dir, "report", "assessment-results.json")}`);
    return 0;
  }

  if (cmd === "export" && sub === "finding") {
    if (more[0] === "validate" || flags["validate"] === true) {
      const path = more[0] === "validate" ? more[1] : more[0];
      const file = path ?? fail("export finding validate <file>");
      const doc = JSON.parse(readFileSync(file, "utf8"));
      const v = validateFinding(doc);
      if (!v.ok) fail(`${file}: Finding invalid: ${formatErrors(v)}`);
      const rec = doc as { schema_version?: string; source?: string; resource?: { type?: string; id?: string } };
      out(`${file}: valid finding.schema.json v${rec.schema_version}; source ${rec.source}; resource ${rec.resource?.type}:${rec.resource?.id}`);
      return 0;
    }
    const dir = str(flags, "out");
    mkdirSync(dir, { recursive: true });
    const from = str(flags, "from", false);
    if (from) {
      const recPath = str(flags, "record", false);
      const record = recPath ? loadRecord(recPath) : undefined;
      const docs = findingsFromDir({ from, source: str(flags, "source", false) || undefined, record });
      const written = writeFindings(dir, docs);
      for (const w of written) out(`${w.path}: ${w.finding.evaluations.length} evaluations, source ${w.finding.source}, resource ${w.finding.resource.type}:${w.finding.resource.id}`);
      return 0;
    }
    const tracePath = str(flags, "trace");
    const tv = verifyTrace(tracePath);
    if (!tv.ok) fail(`${tracePath}: refusing to export an unverified trace (${tv.reason})`);
    if (!tv.sealed) fail(`${tracePath}: refusing to export an unsealed trace`);
    const decisions = readTrace(tracePath);
    const recPath = str(flags, "record", false);
    const record = recPath ? loadRecord(recPath) : null;
    const sessionId = str(flags, "session", false) || decisions[0]?.session_id || basename(tracePath, ".jsonl");
    const source = str(flags, "source", false) || decisions[0]?.source || "colophon";
    const docs = buildFindings({ decisions, sessionId, source, record });
    const written = writeFindings(dir, docs);
    for (const w of written) out(`${w.path}: ${w.finding.evaluations.length} evaluations, source ${w.finding.source}, resource ${w.finding.resource.type}:${w.finding.resource.id}`);
    return 0;
  }

  if (cmd === "bundle" && sub === "create") {
    const m = createBundle(str(flags, "from"), str(flags, "out"));
    out(`${str(flags, "out")}: ${m.files.length} files, root_sha256 ${m.root_sha256}`);
    return 0;
  }

  if (cmd === "bundle" && sub === "sign") {
    const dir = more[0] ?? fail("bundle sign <dir> --key <key>");
    const manifest = join(dir, "manifest.json");
    const sig = join(dir, "manifest.sigstore.json");
    if (flags["keyless"]) signBlobKeyless({ blob: manifest, out: sig });
    else {
      const key = str(flags, "key");
      signBlobWithKey({ blob: manifest, key, password: str(flags, "password", false), out: sig, signingConfig: offlineSigningConfig(resolve(key, "..")) });
    }
    out(`written: ${sig} (not yet verified; run bundle verify)`);
    return 0;
  }

  if (cmd === "bundle" && sub === "verify") {
    const dir = more[0] ?? fail("bundle verify <dir> --pubkey <pub>");
    const r = verifyBundle({ dir, pubkey: str(flags, "pubkey", false) || undefined, certIdentityRegexp: str(flags, "certificate-identity-regexp", false) || undefined, oidcIssuer: str(flags, "oidc-issuer", false) || undefined, out: str(flags, "out", false) || undefined });
    for (const l of r.lines) out(l);
    for (const f of r.failures) process.stderr.write(`FAIL ${f}\n`);
    out(r.ok ? `verified: ${dir}` : `NOT VERIFIED: ${dir} (${r.failures.length} failure${r.failures.length === 1 ? "" : "s"})`);
    return r.ok ? 0 : 1;
  }

  if (cmd === "demo") {
    await runDemo({ outRoot: str(flags, "out", false) || join("out", "demo"), keyless: flags["keyless"] === true });
    return 0;
  }

  fail(`unknown command: ${positional.join(" ")}\n${USAGE}`);
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: unknown) => {
    const err = e as Error;
    process.stderr.write(`error: ${err?.message ?? String(e)}\n`);
    process.exit(1);
  },
);
