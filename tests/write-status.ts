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
const PARTIAL: Record<string, string> = {
  S37: "The workflow is written and pinned and the static probe passes, but it has never executed: the repository has not been pushed to GitHub, so the keyless Sigstore signing path and the green-run half of the claim are unexercised. Needs: push to a GitHub repo with `id-token: write` and read the run.",
};
const NOTES: Record<string, string> = {
  S32: "Fixture-only by design: interface + fixture reader, no SDK, no live client. A live provider is out of scope and is not claimed.",
  S31: "Foreign PEP: three of eight assess-phase controls are not-satisfied because no Record is bound; this is the honest shape of \"their gate, your packet\".",
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

**${done} done · ${partial} partial · ${rows.length - done - partial} not-started** of ${rows.length} claims (S1–S37, A1–A3).

Not claimed anywhere in this repository: a live AWS collector, an OWASP contribution, in-toto co-authorship, any certification, a green CI run (see S37).

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
