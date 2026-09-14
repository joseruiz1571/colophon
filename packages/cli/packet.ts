/**
 * Session → packet. One function for every source: stage the files, collect
 * evidence, assess the catalog, write the OSCAL AR and narrative (citation
 * guard first), finalize the manifest, sign, verify. Throws on any failure;
 * the caller decides the exit code. Prints SIGNATURE only after verify passed.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { assess, loadCatalog, type ControlResult } from "../catalog/checks.ts";
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

export function verifyCommandFor(signer: Signer, bundleDir: string): string {
  return signer.mode === "key"
    ? `bun packages/cli/main.ts bundle verify ${bundleDir} --pubkey ${signer.pub}\n# or, with cosign alone:\ncosign verify-blob --key ${signer.pub} --bundle ${bundleDir}/manifest.sigstore.json --insecure-ignore-tlog ${bundleDir}/manifest.json`
    : `bun packages/cli/main.ts bundle verify ${bundleDir} --certificate-identity-regexp '${signer.certIdentityRegexp}' --oidc-issuer ${signer.oidcIssuer}`;
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
  const store = new EvidenceStore();
  const ids: { record?: string; trace: string; summary: string; selftest?: string; narrative?: string } = { trace: "", summary: "" };
  if (i.record) ids.record = store.put(i.source, "record", i.record.record).id;
  ids.trace = store.put(i.source, "trace", { path: `trace/${traceName}`, verification: traceCheck, decisions }).id;
  for (const d of decisions) store.put(i.source, "decision", d);
  if (i.selftestPath && existsSync(i.selftestPath)) ids.selftest = store.put(i.source, "gate-selftest", JSON.parse(readFileSync(i.selftestPath, "utf8"))).id;
  for (const e of i.extraEvidence ?? []) store.put(i.source, e.kind, e.payload);
  const counts = { allow: 0, deny: 0, escalate: 0 };
  for (const d of decisions) counts[d.effect]++;
  ids.summary = store.put(i.source, "session-summary", { source: i.source, session_id: i.sessionId, task: i.task, record_sha256: i.record?.record.canonical_sha256 ?? null, decisions: decisions.length, ...counts, deny_rule_ids: [...new Set(decisions.filter((d) => d.effect === "deny").flatMap((d) => d.rule_ids))].sort() }).id;

  const catalog = loadCatalog();
  const baseCtx = { source: i.source, record: i.record?.record ?? null, decisions, trace: traceCheck, store, ids };
  // Pass 1: assess with the limits text only, so the narrative can include the findings.
  const limitsProbe = buildNarrative({ source: i.source, sessionId: i.sessionId, record: baseCtx.record, task: i.task, decisions, results: [], traceOk: traceCheck.ok, verifyCommand: i.verifyCommand });
  const pass1 = assess({ ...baseCtx, narrative: limitsProbe }, catalog);
  const narrative = buildNarrative({ source: i.source, sessionId: i.sessionId, record: baseCtx.record, task: i.task, decisions, results: pass1, traceOk: traceCheck.ok, verifyCommand: i.verifyCommand });
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
  const { results, decisions } = assessToDir({ ...i, out: stage, verifyCommand: verifyCommandFor(i.signer, bundleDir) });

  createBundle(stage, bundleDir);
  const manifest = join(bundleDir, "manifest.json");
  const signaturePath = join(bundleDir, SIGNATURE);
  if (i.signer.mode === "key") signBlobWithKey({ blob: manifest, key: i.signer.key, password: i.signer.password, out: signaturePath, signingConfig: i.signer.signingConfig });
  else signBlobKeyless({ blob: manifest, out: signaturePath });

  const outcome = verifyBundle(i.signer.mode === "key" ? { dir: bundleDir, pubkey: i.signer.pub } : { dir: bundleDir, certIdentityRegexp: i.signer.certIdentityRegexp, oidcIssuer: i.signer.oidcIssuer });
  if (!outcome.ok) throw new Error(`bundle verify failed right after signing ${relative(process.cwd(), bundleDir)}: ${outcome.failures.join("; ")}`);
  return { name: i.name, bundleDir, signaturePath, decisions, results, sessionId: i.sessionId, source: i.source, task: i.task };
}
