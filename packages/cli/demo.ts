/**
 * bun run demo: declarations → signed records → two gated sessions through
 * the MCP gate → four foreign-adapter sessions → six signed, verified packets
 * plus GRC Eng Club Finding JSON beside each packet. Exits 1 on the first
 * failure. Prints SIGNATURE: only after verify passed.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { sealSession } from "../hook/index.ts";
import { normalizeAgentcoreDogwood } from "../adapters/agentcore-dogwood/index.ts";
import { FixtureAwsConfigProvider, normalizeAwsConfig } from "../adapters/aws-config/index.ts";
import { normalizeClaudeHook } from "../adapters/claude-hook/index.ts";
import { cosignVersion, generateKeyPair, offlineSigningConfig, signBlobKeyless, signBlobWithKey, verifyBlob } from "../bundle/sign.ts";
import { loadScenario, runScenario } from "../gate/agent.ts";
import { bindRecord } from "../gate/server.ts";
import { buildRecord, loadDeclaration, type ColophonRecord } from "../schema/record.ts";
import { TraceWriter } from "../trace/trace.ts";
import { buildPacket, type PacketOutput, type Signer } from "./packet.ts";
import { buildFindings, writeFindings } from "../export/finding/index.ts";

const FIXTURES = resolve(import.meta.dir, "../fixtures");
export const DEMO_KEY_PASSWORD = "colophon-demo";

export type DemoOptions = { outRoot: string; keyless: boolean };

function log(msg: string): void {
  process.stdout.write(msg + "\n");
}

function emitFindings(p: PacketOutput, record: ColophonRecord | null): void {
  const dir = join(p.bundleDir, "..", "findings");
  const docs = buildFindings({
    decisions: p.decisions,
    sessionId: p.sessionId,
    source: p.source,
    catalogResults: p.results,
    record,
    task: p.task,
  });
  const written = writeFindings(dir, docs);
  const nEval = docs.reduce((n, d) => n + d.evaluations.length, 0);
  log(`findings ${p.name}: ${written.length} document(s), ${nEval} evaluations (finding.schema.json v1) → ${written[0]!.path.replace(resolve(dir, "../..") + "/", "")}`);
}

export async function runDemo(o: DemoOptions): Promise<PacketOutput[]> {
  const outRoot = resolve(o.outRoot);
  rmSync(outRoot, { recursive: true, force: true });
  mkdirSync(outRoot, { recursive: true });
  const t0 = Date.now();
  log(`colophon demo → ${outRoot}`);
  log(`cosign ${cosignVersion()} · signing: ${o.keyless ? "keyless (ambient OIDC)" : "local key pair (offline)"}`);

  let signer: Signer;
  if (o.keyless) {
    const certIdentityRegexp = process.env["COLOPHON_CERT_IDENTITY_REGEXP"];
    const oidcIssuer = process.env["COLOPHON_OIDC_ISSUER"];
    if (!certIdentityRegexp || !oidcIssuer) throw new Error("keyless signing needs COLOPHON_CERT_IDENTITY_REGEXP and COLOPHON_OIDC_ISSUER");
    signer = { mode: "keyless", certIdentityRegexp, oidcIssuer };
  } else {
    const keys = generateKeyPair(join(outRoot, "keys"), DEMO_KEY_PASSWORD);
    signer = { mode: "key", key: keys.key, pub: keys.pub, password: DEMO_KEY_PASSWORD, signingConfig: offlineSigningConfig(join(outRoot, "keys")) };
  }

  // 1. Declarations → Records → sign → bind (hash, signature, lint)
  const recordsDir = join(outRoot, "records");
  mkdirSync(recordsDir, { recursive: true });
  const records = new Map<string, { path: string; sigPath: string }>();
  for (const f of readdirSync(join(FIXTURES, "declarations")).filter((n) => n.endsWith(".yaml")).sort()) {
    const decl = loadDeclaration(join(FIXTURES, "declarations", f));
    const record = buildRecord(decl);
    const path = join(recordsDir, `${decl.name}.record.json`);
    const sigPath = path.replace(/\.record\.json$/, ".record.sigstore.json");
    await Bun.write(path, JSON.stringify(record, null, 2) + "\n");
    if (signer.mode === "key") signBlobWithKey({ blob: path, key: signer.key, password: signer.password, out: sigPath, signingConfig: signer.signingConfig });
    else signBlobKeyless({ blob: path, out: sigPath });
    if (signer.mode === "key") verifyBlob({ blob: path, bundle: sigPath, pubkey: signer.pub });
    else verifyBlob({ blob: path, bundle: sigPath, certIdentityRegexp: signer.certIdentityRegexp, oidcIssuer: signer.oidcIssuer });
    records.set(decl.name, { path, sigPath });
    log(`record  ${decl.name}: built, signed (${sigPath.replace(outRoot + "/", "")}), sha256 ${record.canonical_sha256.slice(0, 12)}…`);
  }

  const packets: PacketOutput[] = [];
  const pubkeyArg = signer.mode === "key" ? signer.pub : "";

  // 2. Gated sessions through the reference PEP
  for (const f of readdirSync(join(FIXTURES, "scenarios")).filter((n) => n.endsWith(".yaml")).sort()) {
    const scenario = loadScenario(join(FIXTURES, "scenarios", f));
    const rec = records.get(scenario.agent);
    if (!rec) throw new Error(`scenario ${scenario.name} names unknown agent ${scenario.agent}`);
    const sessionId = `${scenario.name}-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}`;
    const dir = join(outRoot, scenario.agent);
    const tracePath = join(dir, "trace", `${sessionId}.jsonl`);
    const selftestOut = join(dir, "selftest.json");
    const upstreamLog = join(dir, "upstream-calls.jsonl");
    const upstream = [process.execPath, resolve(import.meta.dir, "main.ts"), "upstream", "demo"];
    const env: Record<string, string> = signer.mode === "keyless" ? { COLOPHON_CERT_IDENTITY_REGEXP: signer.certIdentityRegexp, COLOPHON_OIDC_ISSUER: signer.oidcIssuer } : {};
    const run = await runScenario({ scenario, recordPath: rec.path, pubkeyPath: pubkeyArg, tracePath, sessionId, upstream, upstreamLog, selfTestOut: selftestOut, env });
    const refused = run.outcomes.filter((x) => x.refused).length;
    log(`session ${scenario.agent}: ${run.outcomes.length} calls, ${refused} refused; tools exposed: ${run.tools.join(", ")}`);
    const bound = bindRecord(rec.path, pubkeyArg || undefined, signer.mode === "keyless" ? signer : undefined);
    const packet = buildPacket({ name: scenario.agent, source: "colophon-gate", sessionId, task: scenario.task, outRoot, tracePath, record: { path: rec.path, sigPath: rec.sigPath, record: bound }, selftestPath: selftestOut, signer });
    packets.push(packet);
    emitFindings(packet, bound);
    log(`packet  ${scenario.agent}: ${packet.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 3. Foreign PEP: Claude Code hook fixture
  {
    const n = normalizeClaudeHook(join(FIXTURES, "claude-hook", "session.jsonl"));
    const tracePath = join(outRoot, "claude-hook", "trace", `${n.sessionId}.jsonl`);
    rmSync(tracePath, { force: true });
    const w = new TraceWriter(tracePath);
    for (const d of n.drafts) w.append(d);
    w.seal();
    packets.push(buildPacket({ name: "claude-hook", source: "claude-hook", sessionId: n.sessionId, task: n.task, outRoot, tracePath, signer }));
    emitFindings(packets.at(-1)!, null);
    log(`packet  claude-hook: ${n.drafts.length} hook events normalized → ${packets.at(-1)!.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 3b. Colophon as the PEP inside Claude Code: raw PreToolUse events piped through
  //     the real `hook` command one process per call (as Claude Code would), then `seal`.
  {
    const rec = records.get("claude-coder");
    if (!rec) throw new Error("demo declarations must include claude-coder (Claude Code hook Record)");
    const traceDir = join(outRoot, "claude-coder", "hook");
    rmSync(traceDir, { recursive: true, force: true });
    const events = readFileSync(join(FIXTURES, "claude-hook", "events.jsonl"), "utf8").split("\n").filter((l) => l.trim().length > 0);
    const hookArgs = [resolve(import.meta.dir, "main.ts"), "hook", "--record", rec.path, "--trace-dir", traceDir, ...(pubkeyArg ? ["--pubkey", pubkeyArg] : [])];
    const env: Record<string, string> = { ...(process.env as Record<string, string>), ...(signer.mode === "keyless" ? { COLOPHON_CERT_IDENTITY_REGEXP: signer.certIdentityRegexp, COLOPHON_OIDC_ISSUER: signer.oidcIssuer } : {}) };
    let sessionId = "";
    const tally = { allow: 0, deny: 0, ask: 0 };
    for (const line of events) {
      const r = spawnSync(process.execPath, hookArgs, { input: line, encoding: "utf8", env });
      if (r.status !== 0) throw new Error(`hook exited ${r.status}: ${r.stderr}`);
      const decision = (JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: "allow" | "deny" | "ask" } }).hookSpecificOutput.permissionDecision;
      tally[decision]++;
      sessionId = (JSON.parse(line) as { session_id: string }).session_id;
    }
    const bound = bindRecord(rec.path, pubkeyArg || undefined, signer.mode === "keyless" ? signer : undefined);
    const packet = sealSession({ sessionId, traceDir, recordPath: rec.path, pubkeyPath: pubkeyArg || undefined, outRoot, signer, name: "claude-coder" });
    packets.push(packet);
    emitFindings(packet, bound);
    log(`packet  claude-coder: ${events.length} PreToolUse events through the hook (${tally.allow} allow, ${tally.deny} deny, ${tally.ask} ask) → ${packet.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 4. Foreign PEP: AWS fixture (interface + fixture reader only)
  {
    const n = await normalizeAwsConfig(new FixtureAwsConfigProvider(join(FIXTURES, "aws")));
    const tracePath = join(outRoot, "aws-config", "trace", `${n.sessionId}.jsonl`);
    rmSync(tracePath, { force: true });
    const w = new TraceWriter(tracePath);
    for (const d of n.drafts) w.append(d);
    w.seal();
    packets.push(buildPacket({ name: "aws-config", source: "aws-config", sessionId: n.sessionId, task: n.task, outRoot, tracePath, extraEvidence: n.evidence, signer }));
    emitFindings(packets.at(-1)!, null);
    log(`packet  aws-config: ${n.drafts.length} CloudTrail events normalized (fixture only) → ${packets.at(-1)!.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 5. Foreign PEP: AgentCore Gateway + Dogwood fixture (no live AWS)
  {
    const rec = records.get("red-team-coder");
    if (!rec) throw new Error("demo declarations must include red-team-coder (AgentCore/Dogwood RoE Record)");
    const n = normalizeAgentcoreDogwood(join(FIXTURES, "agentcore-dogwood", "session.jsonl"));
    const bound = bindRecord(rec.path, pubkeyArg || undefined, signer.mode === "keyless" ? signer : undefined);
    const drafts = n.drafts.map((d) => ({ ...d, record_sha256: bound.canonical_sha256 }));
    const tracePath = join(outRoot, "agentcore-dogwood", "trace", `${n.sessionId}.jsonl`);
    rmSync(tracePath, { force: true });
    const w = new TraceWriter(tracePath);
    for (const d of drafts) w.append(d);
    w.seal();
    packets.push(buildPacket({ name: "agentcore-dogwood", source: "agentcore-dogwood", sessionId: n.sessionId, task: n.task, outRoot, tracePath, record: { path: rec.path, sigPath: rec.sigPath, record: bound }, extraEvidence: n.evidence, signer }));
    emitFindings(packets.at(-1)!, bound);
    log(`packet  agentcore-dogwood: ${drafts.length} AgentCore/Dogwood decisions normalized (fixture only) → ${packets.at(-1)!.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 6. Foreign PEP: live AgentCore Gateway APPLICATION_LOGS capture (offline; session id from sidecar)
  {
    const rec = records.get("colophon-roe");
    if (!rec) throw new Error("demo declarations must include colophon-roe (live APPLICATION_LOGS RoE Record)");
    const n = normalizeAgentcoreDogwood(join(FIXTURES, "agentcore-dogwood", "live-roe-7461903f.jsonl"));
    const bound = bindRecord(rec.path, pubkeyArg || undefined, signer.mode === "keyless" ? signer : undefined);
    const drafts = n.drafts.map((d) => ({ ...d, record_sha256: bound.canonical_sha256 }));
    const tracePath = join(outRoot, "agentcore-dogwood-live", "trace", `${n.sessionId}.jsonl`);
    rmSync(tracePath, { force: true });
    const w = new TraceWriter(tracePath);
    for (const d of drafts) w.append(d);
    w.seal();
    packets.push(buildPacket({ name: "agentcore-dogwood-live", source: "agentcore-dogwood", sessionId: n.sessionId, task: n.task, outRoot, tracePath, record: { path: rec.path, sigPath: rec.sigPath, record: bound }, extraEvidence: n.evidence, signer }));
    emitFindings(packets.at(-1)!, bound);
    log(`packet  agentcore-dogwood-live: ${drafts.length} APPLICATION_LOGS evaluations normalized (session ${n.sessionId}, sidecar metadata; no AWS SDK) → ${packets.at(-1)!.bundleDir.replace(outRoot + "/", "")}`);
  }

  // 6. Summary
  log("");
  log("| packet | decisions | allow | deny | escalate | deny rule ids | controls satisfied |");
  log("|---|---|---|---|---|---|---|");
  for (const p of packets) {
    const c = { allow: 0, deny: 0, escalate: 0 };
    for (const d of p.decisions) c[d.effect]++;
    const ids = [...new Set(p.decisions.filter((d) => d.effect === "deny").flatMap((d) => d.rule_ids))].sort();
    const sat = p.results.filter((r) => r.state === "satisfied").length;
    log(`| ${p.name} | ${p.decisions.length} | ${c.allow} | ${c.deny} | ${c.escalate} | ${ids.join(", ") || "—"} | ${sat}/${p.results.length} |`);
  }
  log("");
  for (const p of packets) {
    if (!existsSync(p.signaturePath)) throw new Error(`signature missing after verify: ${p.signaturePath}`);
    log(`SIGNATURE: ${p.signaturePath}`);
  }
  log(`done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  return packets;
}
