/**
 * Writes STATUS.md from out/probes.json (the last fresh-clone probe run) and
 * SPEC.md (claim text). A claim is `done` only when its probe passed in that
 * run; overrides below downgrade claims whose probe passes statically but
 * whose full meaning has not been exercised.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const probes = JSON.parse(readFileSync(resolve(ROOT, "out/probes.json"), "utf8")) as { head: string; ran_at: string; results: { id: string; pass: boolean; ms: number; detail: string }[] };
const spec = readFileSync(resolve(ROOT, "SPEC.md"), "utf8");
const claims = new Map<string, string>();
for (const line of spec.split("\n")) {
  const m = /^\| (S\d+|A\d+) \| (.+?) \| `/.exec(line);
  if (m) claims.set(m[1]!, m[2]!);
}
const PARTIAL: Record<string, string> = {};
const NOTES: Record<string, string> = {
  S37: "CI ran green on the first push: https://github.com/joseruiz1571/colophon/actions/runs/34505148818 (2026-09-10). The keyless demo signed four bundles against the public Sigstore instance and `bundle verify` passed with the pinned certificate identity and issuer; the fresh-clone probe suite passed in full inside CI (40 claims at the time; the count above is current). Actions are pinned to commit SHAs.",
  S32: "Fixture-only by design: interface + fixture reader, no SDK, no live client. A live provider is out of scope and is not claimed.",
  S31: "Foreign PEP: three of eight assess-phase controls are not-satisfied because no Record is bound; this is the honest shape of \"their gate, your packet\".",
  S38: "AuthorizeAction fixture replay. Colophon does not reimplement Dogwood. APPLICATION_LOGS capture ingest is S40. No CloudWatch/EventBridge SDK client. aws-config remains a separate CloudTrail/IAM adapter.",
  S39: "Finding export is club interop on the Decision stream, not a CloudTrail collector. SCF control IDs are not emitted. Dual-emit of CloudTrail is deferred.",
  S40: "Phase 4 is captured APPLICATION_LOGS JSONL ingest, not a live CloudWatch collector. Session id is sidecar/CLI metadata — AgentCore Gateway logs do not carry it. ENFORCE + AWS_IAM named principal. No AWS SDK.",
  S49: "Statement files are the get-policy text with the account id masked and the IAM principal generalized (the D28 rule applied to policy text); the hash is over the redacted bytes and the narrative says so. Not claimed: byte identity with what AWS enforced, or a re-run of Cedar/Dogwood.",
  S50: "COL-11 reads not-satisfied on the claude-hook, aws-config, and AuthorizeAction-fixture packets by design: nothing binds their verdicts to a policy text, and the catalog says so rather than passing vacuously. Verify-time re-evaluation against the bundled policy is deferred (D33).",
  S44: "Exercised by piping the events fixture through the `hook` command one process per call, as Claude Code does; the stdin/stdout contract is from the Claude Code hooks reference (2026-09-16). Not yet exercised inside a live Claude Code session from the build machine, which cannot nest a `claude` process; docs/claude-code.md is the recipe. About half a second per call.",
};
const short = (s: string) => (s.length > 150 ? s.slice(0, 147) + "…" : s);
const rows = probes.results.map((r) => {
  const status = !r.pass ? "not-started" : PARTIAL[r.id] ? "partial" : "done";
  const note = PARTIAL[r.id] ?? NOTES[r.id] ?? (r.pass ? "" : "probe failed in the last run");
  return `| ${r.id} | ${short(claims.get(r.id) ?? "")} | ${status} | \`bun tests/probes.ts\` ${r.id} at ${probes.head}, ${(r.ms / 1000).toFixed(1)}s | ${note} |`;
});
const done = rows.filter((r) => r.includes("| done |")).length;
const partial = rows.filter((r) => r.includes("| partial |")).length;
const out = `# STATUS

Probe run: \`bun tests/probes.ts\` at HEAD \`${probes.head}\`, ${probes.ran_at}, from a fresh \`git clone\` into a temp directory with \`bun install --frozen-lockfile\`. Bun 1.4.0, OPA 1.19.1, Cosign v3.1.3, jq 1.8.2, gitleaks 8.30.1, macOS. Results file: \`out/probes.json\` (gitignored; regenerate with the command above). This file is generated from that run and committed afterwards, so the HEAD it cites is the commit immediately before the one that adds it; rerunning the probes at the STATUS commit itself is how a reader confirms nothing moved.

A row is \`done\` only if its probe passed in that run. \`partial\` means the probe passed but the claim's full meaning was not exercised, with the reason stated. \`not-started\` means the probe failed or did not run.

**${done} done · ${partial} partial · ${rows.length - done - partial} not-started** of ${rows.length} claims (S1–S${Math.max(...probes.results.map((r) => Number(/^S(\d+)$/.exec(r.id)?.[1] ?? 0)))}, A1–A3).

Not claimed anywhere in this repository: a live CloudWatch/EventBridge collector, an OWASP contribution, in-toto co-authorship, any certification.

| # | claim | status | probe run | note |
|---|---|---|---|---|
${rows.join("\n")}

## What "done" means here

- Fresh clone: \`bun run demo\` exits 0 and writes a Cosign 3 bundle (\`manifest.sigstore.json\`) per packet — S16, S29.
- Tamper one trace byte → \`trace verify\` names the line — S14; tamper, add, or remove a bundle file → \`bundle verify\` names the file — S28.
- Missing signature → \`bundle verify\` exits 1 — S29; signing failure → demo exits 1 with no \`SIGNATURE:\` line — S19.
- Four distinct deny rule ids in the evidence-reader trace, a fifth on the notifier — S17.
- Verdicts only from Rego: a one-line policy edit flips a decision with zero \`.ts\` changes — S9; OPA failure denies — S10.
- STATUS matches probes: this file is generated from the probe run it cites (\`tests/write-status.ts\`).
- DECISIONS has no fictional operator — S35.
`;
writeFileSync(resolve(ROOT, "STATUS.md"), out);
console.log(`STATUS.md: ${done} done, ${partial} partial, ${rows.length - done - partial} not-started at ${probes.head}`);
