/**
 * Session → packet. One function for every source: stage the files, collect
 * evidence, assess the catalog, write the OSCAL AR and narrative (citation
 * guard first), finalize the manifest, sign, verify. Throws on any failure;
 * the caller decides the exit code. Prints SIGNATURE only after verify passed.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { assess, COLOPHON_PEP_SOURCES, loadCatalog, type ControlResult, type StagedPolicy } from "../catalog/checks.ts";
import { gatePolicyPath } from "../gate/eval.ts";
import { createBundle, hashFile, SIGNATURE } from "../bundle/manifest.ts";
import { signBlobKeyless, signBlobWithKey } from "../bundle/sign.ts";
import { verifyBundle } from "../bundle/verify.ts";
import { EvidenceStore } from "../evidence/store.ts";
import type { Decision } from "../normalize/decision.ts";
import { buildNarrative } from "../report/narrative.ts";
import { buildAssessmentResults, validateOscal } from "../report/oscal.ts";
import type { ColophonRecord } from "../schema/record.ts";
import { headPath, readTrace, verifyTrace } from "../trace/trace.ts";

export type Signer =
  | { mode: "key"; key: string; pub: string; password: string; signingConfig: string }
  | { mode: "keyless"; certIdentityRegexp: string; oidcIssuer: string };

export type PacketInput = {
  name: string;
  source: string;
  sessionId: string;
  task: string;
  outRoot: string;
  tracePath: string;
  record?: { path: string; sigPath: string; record: ColophonRecord };
  selftestPath?: string;
  extraEvidence?: { kind: string; payload: unknown }[];
  signer: Signer;
};

export type PacketOutput = {
  name: string;
  bundleDir: string;
  signaturePath: string;
  decisions: Decision[];
  results: ControlResult[];
  sessionId: string;
  source: string;
  task: string;
};

const CATALOG_PATH = join(import.meta.dir, "../catalog/controls.yaml");

/** Paths inside a packet are relative to the directory it was built from, never the build machine's absolute path: a portable receipt must read the same on every machine. */
export function portablePath(p: string): string {
  const r = relative(process.cwd(), p);
  return r.length > 0 && !r.startsWith("..") ? r : p;
}

export function verifyCommandFor(signer: Signer, bundleDir: string): string {
  const b = portablePath(bundleDir);
  return signer.mode === "key"
    ? `bun packages/cli/main.ts bundle verify ${b} --pubkey ${portablePath(signer.pub)}\n# or, with cosign alone:\ncosign verify-blob --key ${portablePath(signer.pub)} --bundle ${b}/manifest.sigstore.json --insecure-ignore-tlog ${b}/manifest.json`
    : `bun packages/cli/main.ts bundle verify ${b} --certificate-identity-regexp '${signer.certIdentityRegexp}' --oidc-issuer ${signer.oidcIssuer}`;
}

export class PolicyBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyBindingError";
  }
}

/**
 * Stage the policy text the verdicts came from under <stage>/policy/, so the
 * manifest hashes it and a verifier can compare. Two bindings, one rule each:
 *   - a Colophon PEP (gate, hook) stamps policy_sha256 on every Decision; the
 *     staged gate.rego must hash to exactly that value, or nothing is staged
 *     and the packet is refused (a packet must not carry a policy its verdicts
 *     did not come from);
 *   - a foreign PEP's Record declares pep.policies with the hash of each
 *     statement file; every file must exist and hash as declared.
 * Decisions without policy_sha256 (the OPA-error path, or an older trace)
 * stage nothing and leave COL-11 to say so.
 */
export function stagePolicies(stage: string, source: string, decisions: Decision[], record: ColophonRecord | null): StagedPolicy[] {
  const out: StagedPolicy[] = [];
  const policyDir = join(stage, "policy");
  if (COLOPHON_PEP_SOURCES.has(source)) {
    const carried = [...new Set(decisions.map((d) => d.policy_sha256).filter((h): h is string => typeof h === "string"))];
    if (carried.length > 0) {
      const src = gatePolicyPath();
      if (!existsSync(src)) throw new PolicyBindingError(`${carried.length === 1 ? "the decisions carry" : "decisions carry"} policy_sha256 but the gate policy ${portablePath(src)} is not readable; there is no policy text to stage`);
      const h = hashFile(src).sha256;
      if (carried.length > 1 || carried[0] !== h) {
        throw new PolicyBindingError(`policy_sha256 mismatch: decisions carry ${carried.map((x) => x.slice(0, 12) + "…").join(", ")} but ${portablePath(src)} hashes to ${h.slice(0, 12)}…; refusing to stage a policy the verdicts did not come from`);
      }
      mkdirSync(policyDir, { recursive: true });
      copyFileSync(src, join(policyDir, "gate.rego"));
      out.push({ role: "gate", path: "policy/gate.rego", sha256: h });
    }
  }
  for (const p of record?.declaration.pep?.policies ?? []) {
    const src = resolve(process.cwd(), p.path);
    const name = record!.declaration.name;
    if (!existsSync(src)) throw new PolicyBindingError(`Record ${name} declares policy ${p.id} at ${p.path}, which does not exist`);
    const h = hashFile(src).sha256;
    if (h !== p.sha256) throw new PolicyBindingError(`Record ${name} declares policy ${p.id} with sha256 ${p.sha256.slice(0, 12)}… but ${p.path} hashes to ${h.slice(0, 12)}…`);
    const file = `${p.id.replace(/[^A-Za-z0-9._-]/g, "_")}.cedar`;
    mkdirSync(policyDir, { recursive: true });
    copyFileSync(src, join(policyDir, file));
    out.push({ role: "declared", id: p.id, kind: p.kind, path: `policy/${file}`, sha256: h });
  }
  return out;
}

/** Assess-only: evidence + AR + narrative into <out>/{evidence,report}. No bundle, no signature. */
export function assessToDir(i: Omit<PacketInput, "signer" | "outRoot" | "name"> & { out: string; verifyCommand: string }): { results: ControlResult[]; decisions: Decision[] } {
  const stage = i.out;
  mkdirSync(join(stage, "report"), { recursive: true });
  mkdirSync(join(stage, "trace"), { recursive: true });
  mkdirSync(join(stage, "catalog"), { recursive: true });
  const start = new Date().toISOString();

  const traceName = basename(i.tracePath);
  if (!existsSync(headPath(i.tracePath))) throw new Error(`trace is not sealed (${headPath(i.tracePath)} missing); refusing to package a trace without its head commitment`);
  copyFileSync(i.tracePath, join(stage, "trace", traceName));
  copyFileSync(headPath(i.tracePath), join(stage, "trace", basename(headPath(i.tracePath))));
  copyFileSync(CATALOG_PATH, join(stage, "catalog", "controls.yaml"));
  if (i.record) {
    mkdirSync(join(stage, "records"), { recursive: true });
    copyFileSync(i.record.path, join(stage, "records", basename(i.record.path)));
    copyFileSync(i.record.sigPath, join(stage, "records", basename(i.record.sigPath)));
  }

  const traceCheck = verifyTrace(i.tracePath);
  const decisions = readTrace(i.tracePath);
  const policies = stagePolicies(stage, i.source, decisions, i.record?.record ?? null);
  const store = new EvidenceStore();
  const ids: { record?: string; trace: string; summary: string; selftest?: string; narrative?: string; policies?: string } = { trace: "", summary: "" };
  if (i.record) ids.record = store.put(i.source, "record", i.record.record).id;
  if (policies.length > 0) ids.policies = store.put(i.source, "policies", { files: policies }).id;
  ids.trace = store.put(i.source, "trace", { path: `trace/${traceName}`, verification: traceCheck, decisions }).id;
  for (const d of decisions) store.put(i.source, "decision", d);
  if (i.selftestPath && existsSync(i.selftestPath)) ids.selftest = store.put(i.source, "gate-selftest", JSON.parse(readFileSync(i.selftestPath, "utf8"))).id;
  for (const e of i.extraEvidence ?? []) store.put(i.source, e.kind, e.payload);
  const counts = { allow: 0, deny: 0, escalate: 0 };
  for (const d of decisions) counts[d.effect]++;
  ids.summary = store.put(i.source, "session-summary", { source: i.source, session_id: i.sessionId, task: i.task, record_sha256: i.record?.record.canonical_sha256 ?? null, decisions: decisions.length, ...counts, deny_rule_ids: [...new Set(decisions.filter((d) => d.effect === "deny").flatMap((d) => d.rule_ids))].sort() }).id;

  const catalog = loadCatalog();
  const baseCtx = { source: i.source, record: i.record?.record ?? null, decisions, trace: traceCheck, store, ids, policies };
  // Pass 1: assess with the limits text only, so the narrative can include the findings.
  const limitsProbe = buildNarrative({ source: i.source, sessionId: i.sessionId, record: baseCtx.record, task: i.task, decisions, results: [], traceOk: traceCheck.ok, verifyCommand: i.verifyCommand, policies });
  const pass1 = assess({ ...baseCtx, narrative: limitsProbe }, catalog);
  const narrative = buildNarrative({ source: i.source, sessionId: i.sessionId, record: baseCtx.record, task: i.task, decisions, results: pass1, traceOk: traceCheck.ok, verifyCommand: i.verifyCommand, policies });
  ids.narrative = store.put(i.source, "narrative", { path: "report/narrative.md", text: narrative }).id;
  // Pass 2: same checks, now citing the narrative evidence item.
  const results = assess({ ...baseCtx, ids, narrative }, catalog);
  const end = new Date().toISOString();

  store.writeTo(join(stage, "evidence"));
  writeFileSync(join(stage, "report", "narrative.md"), narrative);
  const doc = buildAssessmentResults({
    title: `Colophon assessment — ${i.sessionId} (${i.source})`,
    description: i.task,
    source: i.source,
    sessionId: i.sessionId,
    recordSha256: i.record?.record.canonical_sha256,
    results,
    store,
    evidenceDir: "evidence",
    extraResources: [
      { key: "catalog", title: "Colophon control catalog", href: "catalog/controls.yaml", sha256: hashFile(CATALOG_PATH).sha256, mediaType: "application/yaml", description: "The control set evaluated; stands in for an assessment plan." },
      { key: "narrative", title: "Narrative report", href: "report/narrative.md", sha256: hashFile(join(stage, "report", "narrative.md")).sha256, mediaType: "text/markdown", description: "Human-readable report with the proves / does-not-prove table." },
    ],
    start,
    end,
  });
  const v = validateOscal(doc);
  if (!v.ok) throw new Error(`assessment-results.json would not validate against OSCAL ${"1.2.3"}: ${v.errors.join("; ")}`);
  writeFileSync(join(stage, "report", "assessment-results.json"), JSON.stringify(doc, null, 2) + "\n");
  writeFileSync(join(stage, "session.json"), JSON.stringify({ source: i.source, session_id: i.sessionId, task: i.task, start, end, record: i.record ? basename(i.record.path) : null }, null, 2) + "\n");
  return { results, decisions };
}

export function buildPacket(i: PacketInput): PacketOutput {
  const root = join(i.outRoot, i.name);
  const stage = join(root, "stage");
  const bundleDir = join(root, "bundle");
  rmSync(stage, { recursive: true, force: true });
  rmSync(bundleDir, { recursive: true, force: true });
  let assessed: { results: ControlResult[]; decisions: Decision[] };
  try {
    assessed = assessToDir({ ...i, out: stage, verifyCommand: verifyCommandFor(i.signer, bundleDir) });
  } catch (e) {
    // A policy the verdicts did not come from is never sealed under a
    // signature. Same shape as the COL-10 refusal below: no bundle, no stage.
    if (e instanceof PolicyBindingError) {
      rmSync(stage, { recursive: true, force: true });
      throw new Error(`refusing to sign ${i.name}: ${e.message}`);
    }
    throw e;
  }
  const { results, decisions } = assessed;

  // A credential-shaped value that survived redaction is not sealed into a
  // signed packet with a red row next to it. Refuse before the bundle exists,
  // and remove the staged copy so the value is not left under out/.
  const leak = results.find((r) => r.control.check === "secrets-redacted" && r.state === "not-satisfied");
  if (leak) {
    rmSync(stage, { recursive: true, force: true });
    throw new Error(`refusing to sign ${i.name}: ${leak.control.id} not-satisfied — ${leak.rationale}`);
  }

  createBundle(stage, bundleDir);
  const manifest = join(bundleDir, "manifest.json");
  const signaturePath = join(bundleDir, SIGNATURE);
  if (i.signer.mode === "key") signBlobWithKey({ blob: manifest, key: i.signer.key, password: i.signer.password, out: signaturePath, signingConfig: i.signer.signingConfig });
  else signBlobKeyless({ blob: manifest, out: signaturePath });

  const outcome = verifyBundle(i.signer.mode === "key" ? { dir: bundleDir, pubkey: i.signer.pub } : { dir: bundleDir, certIdentityRegexp: i.signer.certIdentityRegexp, oidcIssuer: i.signer.oidcIssuer });
  if (!outcome.ok) throw new Error(`bundle verify failed right after signing ${relative(process.cwd(), bundleDir)}: ${outcome.failures.join("; ")}`);
  return { name: i.name, bundleDir, signaturePath, decisions, results, sessionId: i.sessionId, source: i.source, task: i.task };
}
