/**
 * The reference PEP: an MCP stdio server that sits between an agent and an
 * upstream tool server. Every tools/call is decided by Rego through OPA,
 * appended to the hash-chained trace, and forwarded only on allow.
 *
 * Startup is fail-closed: the Record must validate, its hashes must
 * recompute, its Cosign signature must verify against the given public key,
 * and record lint must pass. Any failure exits 1 before a transport opens.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { verifyBlob } from "../bundle/sign.ts";
import { argsSha256, redactArgs } from "../normalize/decision.ts";
import { RECORD_POLICY, opaEval } from "../policy/opa.ts";
import { loadRecord, verifyRecordHashes, type ColophonRecord } from "../schema/record.ts";
import { TraceWriter } from "../trace/trace.ts";
import { decide, policySha256, selfTest, type Verdict } from "./eval.ts";

export type GateOptions = {
  recordPath: string;
  pubkeyPath: string;
  upstream: string[];
  tracePath: string;
  sessionId: string;
  selfTestOnly?: boolean;
  selfTestOut?: string;
};

export class GateStartupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GateStartupError";
  }
}

export function recordSignaturePath(recordPath: string): string {
  return recordPath.replace(/\.record\.json$/, ".record.sigstore.json");
}

export type LintResult = { ok: boolean; denies: { rule_id: string; field: string; msg: string }[] };

export function lintRecord(record: ColophonRecord): LintResult {
  const value = opaEval(RECORD_POLICY, record, "data.colophon.record.result") as LintResult;
  if (typeof value?.ok !== "boolean" || !Array.isArray(value.denies)) throw new GateStartupError("record lint returned a malformed result");
  return value;
}

/** Load, hash-verify, signature-verify, and lint a Record. Throws GateStartupError. */
export type KeylessIdentity = { certIdentityRegexp: string; oidcIssuer: string };

export function keylessFromEnv(): KeylessIdentity | undefined {
  const certIdentityRegexp = process.env["COLOPHON_CERT_IDENTITY_REGEXP"];
  const oidcIssuer = process.env["COLOPHON_OIDC_ISSUER"];
  return certIdentityRegexp && oidcIssuer ? { certIdentityRegexp, oidcIssuer } : undefined;
}

export function bindRecord(recordPath: string, pubkeyPath?: string, keyless: KeylessIdentity | undefined = keylessFromEnv()): ColophonRecord {
  let record: ColophonRecord;
  try {
    record = loadRecord(recordPath);
  } catch (e) {
    throw new GateStartupError(`record rejected: ${(e as Error).message}`);
  }
  const hashProblem = verifyRecordHashes(record);
  if (hashProblem) throw new GateStartupError(`record rejected: ${hashProblem}`);
  const sig = recordSignaturePath(recordPath);
  if (!existsSync(sig)) throw new GateStartupError(`record rejected: signature file missing (${sig})`);
  if (!pubkeyPath && !keyless) throw new GateStartupError("record rejected: no public key (--pubkey) and no keyless identity (COLOPHON_CERT_IDENTITY_REGEXP + COLOPHON_OIDC_ISSUER); cannot verify the record signature");
  try {
    if (pubkeyPath) verifyBlob({ blob: recordPath, bundle: sig, pubkey: pubkeyPath });
    else verifyBlob({ blob: recordPath, bundle: sig, certIdentityRegexp: keyless!.certIdentityRegexp, oidcIssuer: keyless!.oidcIssuer });
  } catch (e) {
    throw new GateStartupError(`record rejected: signature does not verify: ${(e as Error).message}`);
  }
  const lint = lintRecord(record);
  if (!lint.ok) throw new GateStartupError(`record rejected by lint: ${lint.denies.map((d) => `${d.rule_id} (${d.field}): ${d.msg}`).join("; ")}`);
  return record;
}

function parseUpstream(upstream: string[]): { command: string; args: string[] } {
  const [command, ...args] = upstream;
  if (!command) throw new GateStartupError("no upstream command");
  return { command, args };
}

export async function runGate(opts: GateOptions): Promise<void> {
  const record = bindRecord(opts.recordPath, opts.pubkeyPath || undefined);
  const st = selfTest(record);
  if (!st.ok) throw new GateStartupError(`fail-closed self-test failed: ${JSON.stringify(st)}`);
  if (opts.selfTestOut) {
    mkdirSync(dirname(opts.selfTestOut), { recursive: true });
    writeFileSync(opts.selfTestOut, JSON.stringify({ record_sha256: record.canonical_sha256, ...st }, null, 2) + "\n");
  }
  if (opts.selfTestOnly) {
    process.stderr.write(`[gate] self-test ok: record ${record.declaration.name} bound, unknown tool denied, OPA error denied\n`);
    return;
  }

  const { command, args } = parseUpstream(opts.upstream);
  const upstream = new Client({ name: "colophon-gate", version: "0.1.0" });
  await upstream.connect(new StdioClientTransport({ command, args, env: { ...process.env } as Record<string, string>, stderr: "inherit" }));
  const upstreamTools = (await upstream.listTools()).tools;
  const declared = new Set(record.declaration.tools.map((t) => t.name));
  const exposed = upstreamTools.filter((t) => declared.has(t.name));

  const trace = new TraceWriter(opts.tracePath);
  let callIndex = trace.length;

  const server = new Server({ name: "colophon-gate", version: "0.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: exposed }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const argsIn = (req.params.arguments ?? {}) as Record<string, unknown>;
    const context = { session_id: opts.sessionId, call_index: callIndex++ };
    const verdict: Verdict = decide(record, { name, arguments: argsIn }, context);
    // Hashed per call, never cached at startup: the Decision names the bytes
    // that were on disk when this verdict was produced.
    const policyHash = policySha256();
    trace.append({
      source: "colophon-gate",
      effect: verdict.effect,
      rule_ids: verdict.rule_ids,
      reasons: verdict.reasons,
      tool: name,
      args_sha256: argsSha256(argsIn),
      args_redacted: redactArgs(argsIn),
      session_id: context.session_id,
      call_index: context.call_index,
      record_sha256: record.canonical_sha256,
      ...(policyHash ? { policy_sha256: policyHash } : {}),
      ts: new Date().toISOString(),
    });
    if (verdict.effect !== "allow") {
      return { isError: true, content: [{ type: "text", text: JSON.stringify({ refused: true, ...verdict }) }] };
    }
    const result = await upstream.callTool({ name, arguments: argsIn });
    return result as { content: { type: "text"; text: string }[] };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Stay alive until the client closes the pipe; otherwise main() would exit and the client sees "Connection closed".
  await new Promise<void>((done) => {
    transport.onclose = () => done();
  });
  await upstream.close();
}
