/**
 * Stranger's verification: directory + public key (or certificate identity).
 *   1. manifest: every listed file present with matching hash; nothing extra.
 *   2. signature: manifest.sigstore.json verifies over manifest.json.
 *   3. OSCAL walk: each observation's relevant-evidence → back-matter resource
 *      → rlink href → file listed in manifest with matching SHA-256.
 *   4. trace chains re-verify.
 * Fails closed: no key and no identity means no verification, exit 1.
 * With --out, writes a second OSCAL AR for the verify-phase controls.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { policySetHash, verifyPhaseControls, type ControlResult } from "../catalog/checks.ts";
import { EvidenceStore } from "../evidence/store.ts";
import { buildAssessmentResults, validateOscal } from "../report/oscal.ts";
import { readTrace, verifyTrace } from "../trace/trace.ts";
import { loadRecord, verifyRecordHashes, type ColophonRecord } from "../schema/record.ts";
import { checkManifest, hashFile, listFiles, MANIFEST, SIGNATURE, type Manifest } from "./manifest.ts";
import { SignError, verifyBlob } from "./sign.ts";

export type VerifyBundleOptions = {
  dir: string;
  pubkey?: string;
  certIdentityRegexp?: string;
  oidcIssuer?: string;
  out?: string;
};

export type VerifyOutcome = { ok: boolean; lines: string[]; failures: string[]; rlinks: { resolved: number; unresolved: number } };

function walkOscal(dir: string, manifest: Manifest, lines: string[], failures: string[]): { resolved: number; unresolved: number } {
  const arPath = join(dir, "report", "assessment-results.json");
  if (!existsSync(arPath)) {
    failures.push(`report/assessment-results.json missing`);
    return { resolved: 0, unresolved: 0 };
  }
  const doc = JSON.parse(readFileSync(arPath, "utf8")) as { "assessment-results": { results: { observations?: { uuid: string; "relevant-evidence"?: { href: string }[] }[]; findings?: { "related-observations"?: { "observation-uuid": string }[] }[] }[]; "back-matter"?: { resources?: { uuid: string; rlinks?: { href: string; hashes?: { algorithm: string; value: string }[] }[] }[] } } };
  const v = validateOscal(doc);
  if (!v.ok) failures.push(`assessment-results.json fails OSCAL schema: ${v.errors[0]}`);
  const byPath = new Map(manifest.files.map((f) => [f.path, f]));
  const resources = new Map((doc["assessment-results"]["back-matter"]?.resources ?? []).map((r) => [r.uuid, r]));
  const observations = new Map<string, { uuid: string; "relevant-evidence"?: { href: string }[] }>();
  let resolved = 0;
  let unresolved = 0;
  for (const result of doc["assessment-results"].results) {
    for (const o of result.observations ?? []) observations.set(o.uuid, o);
    for (const f of result.findings ?? []) {
      for (const ro of f["related-observations"] ?? []) {
        if (!observations.has(ro["observation-uuid"])) {
          unresolved++;
          failures.push(`finding cites observation ${ro["observation-uuid"]} which does not exist`);
        }
      }
    }
    for (const o of result.observations ?? []) {
      for (const ev of o["relevant-evidence"] ?? []) {
        const uuid = ev.href.startsWith("#") ? ev.href.slice(1) : null;
        const res = uuid ? resources.get(uuid) : undefined;
        if (!res) {
          unresolved++;
          failures.push(`observation ${o.uuid} cites ${ev.href} which is not a back-matter resource`);
          continue;
        }
        for (const rl of res.rlinks ?? []) {
          const entry = byPath.get(rl.href);
          const stated = rl.hashes?.find((h) => h.algorithm === "SHA-256")?.value;
          if (!entry) {
            unresolved++;
            failures.push(`resource ${res.uuid} rlink ${rl.href} is not in the manifest`);
          } else if (!stated || stated !== entry.sha256) {
            unresolved++;
            failures.push(`resource ${res.uuid} rlink ${rl.href}: OSCAL hash ${stated ?? "missing"} != manifest ${entry.sha256}`);
          } else {
            resolved++;
          }
        }
      }
    }
  }
  lines.push(`oscal: schema ${v.ok ? "ok" : "INVALID"}; rlinks: ${resolved} resolved, unresolved: ${unresolved}`);
  return { resolved, unresolved };
}

export function verifyBundle(o: VerifyBundleOptions): VerifyOutcome {
  const lines: string[] = [];
  const failures: string[] = [];
  const results: ControlResult[] = [];
  const controls = verifyPhaseControls();
  const manifestControl = controls.find((c) => c.check === "manifest-complete")!;
  const sigControl = controls.find((c) => c.check === "signature-verifies")!;
  const store = new EvidenceStore();

  if (!existsSync(o.dir)) return { ok: false, lines, failures: [`bundle directory not found: ${o.dir}`], rlinks: { resolved: 0, unresolved: 0 } };

  // 1. manifest
  const mc = checkManifest(o.dir);
  const manifestFile = join(o.dir, MANIFEST);
  const manifestEvidence = existsSync(manifestFile) ? store.put("bundle-verify", "manifest", { path: MANIFEST, ...hashFile(manifestFile), files: listFiles(o.dir).length }) : null;
  if (mc.ok) {
    lines.push(`manifest: ok (${mc.files} files)`);
    results.push({ control: manifestControl, state: "satisfied", rationale: `${mc.files} files listed; every hash and size matches; no unlisted files; root_sha256 recomputes.`, cited: manifestEvidence ? [manifestEvidence.id] : [] });
  } else {
    failures.push(`manifest: ${mc.file}: ${mc.reason}`);
    results.push({ control: manifestControl, state: "not-satisfied", rationale: `${mc.file}: ${mc.reason}`, cited: manifestEvidence ? [manifestEvidence.id] : [] });
  }

  // 2. signature (fail closed when no verification material was presented)
  const sigFile = join(o.dir, SIGNATURE);
  let sigEvidenceId: string | undefined;
  if (existsSync(sigFile)) sigEvidenceId = store.put("bundle-verify", "signature", { path: SIGNATURE, ...hashFile(sigFile) }).id;
  if (!o.pubkey && !(o.certIdentityRegexp && o.oidcIssuer)) {
    failures.push(`signature: no public key (--pubkey) or certificate identity (--certificate-identity-regexp + --oidc-issuer) given; refusing to treat the bundle as verified`);
    results.push({ control: sigControl, state: "not-satisfied", rationale: "No verification material presented.", cited: sigEvidenceId ? [sigEvidenceId] : [] });
  } else if (!existsSync(sigFile)) {
    failures.push(`signature: ${SIGNATURE} missing`);
    results.push({ control: sigControl, state: "not-satisfied", rationale: `${SIGNATURE} is missing from the bundle.`, cited: [] });
  } else {
    try {
      if (o.pubkey) verifyBlob({ blob: manifestFile, bundle: sigFile, pubkey: o.pubkey });
      else verifyBlob({ blob: manifestFile, bundle: sigFile, certIdentityRegexp: o.certIdentityRegexp!, oidcIssuer: o.oidcIssuer! });
      lines.push(`signature: ok (${SIGNATURE} verifies over ${MANIFEST}${o.pubkey ? ` with ${o.pubkey}` : " keyless"})`);
      results.push({ control: sigControl, state: "satisfied", rationale: `cosign verify-blob succeeded over ${MANIFEST} using ${o.pubkey ? "the presented public key" : `certificate identity ${o.certIdentityRegexp} issued by ${o.oidcIssuer}`}.`, cited: sigEvidenceId ? [sigEvidenceId] : [] });
    } catch (e) {
      const msg = e instanceof SignError ? e.message : String(e);
      failures.push(`signature: ${msg}`);
      results.push({ control: sigControl, state: "not-satisfied", rationale: msg, cited: sigEvidenceId ? [sigEvidenceId] : [] });
    }
  }

  // 3. OSCAL walk (only meaningful when the manifest parsed)
  let rlinks = { resolved: 0, unresolved: 0 };
  if (existsSync(manifestFile)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestFile, "utf8")) as Manifest;
      rlinks = walkOscal(o.dir, manifest, lines, failures);
    } catch (e) {
      failures.push(`oscal walk failed: ${(e as Error).message}`);
    }
  }

  // 4. bundled records: hashes, signature (with the presented key/identity), and the trace's record_sha256 binding
  const recordsDir = join(o.dir, "records");
  const recordHashes = new Set<string>();
  const verifiedRecords: { file: string; rec: ColophonRecord }[] = [];
  if (existsSync(recordsDir)) {
    for (const f of listFiles(recordsDir).filter((p) => p.endsWith(".record.json"))) {
      const rp = join(recordsDir, f);
      try {
        const rec = loadRecord(rp);
        const problem = verifyRecordHashes(rec);
        if (problem) {
          failures.push(`record: ${f}: ${problem}`);
          continue;
        }
        const rsig = rp.replace(/\.record\.json$/, ".record.sigstore.json");
        if (!existsSync(rsig)) {
          failures.push(`record: ${f}: signature ${relative(o.dir, rsig)} missing`);
          continue;
        }
        if (o.pubkey) verifyBlob({ blob: rp, bundle: rsig, pubkey: o.pubkey });
        else if (o.certIdentityRegexp && o.oidcIssuer) verifyBlob({ blob: rp, bundle: rsig, certIdentityRegexp: o.certIdentityRegexp, oidcIssuer: o.oidcIssuer });
        else throw new SignError("no verification material for the record signature");
        recordHashes.add(rec.canonical_sha256);
        verifiedRecords.push({ file: f, rec });
        lines.push(`record: ${f} ok (hashes recompute, signature verifies)`);
      } catch (e) {
        failures.push(`record: ${f}: ${(e as Error).message}`);
      }
    }
  }

  // 5. traces: chain, head, and (for gate traces) binding to a bundled record
  const traceDir = join(o.dir, "trace");
  if (existsSync(traceDir)) {
    for (const f of listFiles(traceDir).filter((p) => p.endsWith(".jsonl"))) {
      const tv = verifyTrace(join(traceDir, f));
      if (!tv.ok) {
        failures.push(`trace: ${f}: ${tv.reason}`);
        continue;
      }
      const bound = readTrace(join(traceDir, f)).filter((d) => d.record_sha256);
      const unbound = bound.filter((d) => !recordHashes.has(d.record_sha256!));
      if (unbound.length > 0) failures.push(`trace: ${f}: ${unbound.length} decisions carry record_sha256 ${unbound[0]!.record_sha256} which is not a verified bundled record`);
      else lines.push(`trace: ${f} ok (${tv.lines} decisions, chain intact${tv.sealed ? ", head commitment matches" : ", NO head commitment"}${bound.length ? `, bound to verified record` : ""})`);
    }
  }

  // 5b. policy binding: every policy_sha256 a decision carries, and every
  //     policy a bundled Record declares, must be a file under policy/ with
  //     that exact hash. Reported on its own line so a swapped policy fails on
  //     the binding, not only on the manifest.
  const policyDir = join(o.dir, "policy");
  const staged = new Map<string, string>();
  if (existsSync(policyDir)) for (const f of listFiles(policyDir)) staged.set(hashFile(join(policyDir, f)).sha256, `policy/${f}`);
  if (existsSync(traceDir)) {
    for (const f of listFiles(traceDir).filter((p) => p.endsWith(".jsonl"))) {
      let decisions;
      try {
        decisions = readTrace(join(traceDir, f));
      } catch {
        continue; // already reported by the trace check above
      }
      const carried = [...new Set(decisions.map((d) => d.policy_sha256).filter((h): h is string => typeof h === "string"))];
      if (carried.length === 0) {
        // Colophon decided these and nothing names the policy: said out loud, never silent (COL-11 in the AR carries the finding).
        const colophonPep = decisions.some((d) => d.source === "colophon-gate" || d.source === "colophon-hook");
        if (colophonPep) lines.push(`policy: ${f}: no policy binding carried (${decisions.length} decisions without policy_sha256; see COL-11 in the assessment results)`);
        continue;
      }
      const missing = carried.filter((h) => !staged.has(h));
      if (missing.length > 0) failures.push(`policy: ${f}: ${decisions.filter((d) => missing.includes(d.policy_sha256!)).length} decisions carry policy_sha256 ${missing[0]!} which matches no file under policy/ (binding broken${staged.size ? `; staged: ${[...staged.values()].join(", ")}` : "; nothing staged"})`);
      else lines.push(`policy: ${f}: ${decisions.filter((d) => d.policy_sha256).length} decisions bound to ${carried.map((h) => `${staged.get(h)} (sha256 ${h.slice(0, 12)}…)`).join(", ")}`);
    }
  }
  for (const { file, rec } of verifiedRecords) {
    const declared = rec.declaration.pep?.policies ?? [];
    if (declared.length === 0) continue;
    const bad = declared.filter((p) => staged.get(p.sha256) === undefined);
    if (bad.length > 0) {
      failures.push(`policy: ${file} declares ${bad.map((p) => `${p.id} (sha256 ${p.sha256.slice(0, 12)}…)`).join(", ")} but no file under policy/ has that hash (binding broken)`);
      continue;
    }
    const setHash = rec.declaration.pep?.policy_set_hash;
    if (setHash && setHash !== policySetHash(declared.map((p) => p.sha256))) {
      failures.push(`policy: ${file}: pep.policy_set_hash ${setHash.slice(0, 12)}… does not recompute from the declared policy hashes`);
      continue;
    }
    lines.push(`policy: ${file}: ${declared.length} declared policies staged with matching hashes (${declared.map((p) => p.id).join(", ")})${setHash ? "; policy_set_hash recomputes" : ""}`);
  }

  // 6. verification AR outside the bundle
  if (o.out) {
    mkdirSync(o.out, { recursive: true });
    const now = new Date().toISOString();
    store.writeTo(join(o.out, "evidence"));
    const doc = buildAssessmentResults({
      title: `Colophon verification of ${o.dir}`,
      description: `Verify-phase controls evaluated over the signed bundle at ${o.dir}. Written outside the bundle because a bundle cannot attest to its own signature.`,
      source: "bundle-verify",
      sessionId: `verify:${relative(process.cwd(), o.dir) || o.dir}`,
      results,
      store,
      evidenceDir: "evidence",
      extraResources: [],
      start: now,
      end: now,
    });
    const v = validateOscal(doc);
    if (!v.ok) failures.push(`verification-results.json fails OSCAL schema: ${v.errors.join("; ")}`);
    else writeFileSync(join(o.out, "verification-results.json"), JSON.stringify(doc, null, 2) + "\n");
    lines.push(`verification AR: ${join(o.out, "verification-results.json")} (${results.map((r) => `${r.control.id}=${r.state}`).join(", ")})`);
  }

  return { ok: failures.length === 0, lines, failures, rlinks };
}
