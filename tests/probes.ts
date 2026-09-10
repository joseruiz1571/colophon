/**
 * The STATUS evidence. Clones THIS repository's committed HEAD into a temp
 * directory, installs with a frozen lockfile, runs the demo, then runs every
 * probe from SPEC.md §4 in that fresh clone. Prints one row per claim and
 * writes out/probes.json in the source repo. Exit 1 if any probe fails.
 * Uncommitted changes are NOT visible to the probes — commit first.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const SRC = resolve(import.meta.dir, "..");
const KEEP = process.env["PROBES_KEEP"] === "1";
const tmp = mkdtempSync(join(tmpdir(), "colophon-probes-"));
const clone = join(tmp, "colophon");

type R = { code: number; out: string; err: string; ms: number };
function sh(cmd: string, cwd = clone, env: Record<string, string> = {}): R {
  const t = Date.now();
  const r = spawnSync("bash", ["-eo", "pipefail", "-c", cmd], { cwd, encoding: "utf8", env: { ...process.env, ...env, CLI: "bun packages/cli/main.ts", OUT: "out/demo" }, maxBuffer: 64 * 1024 * 1024, timeout: 600_000 });
  return { code: r.status ?? -1, out: r.stdout ?? "", err: r.stderr ?? "", ms: Date.now() - t };
}
const lines = (s: string) => s.split("\n").filter((l) => l.trim().length > 0);
const last = (s: string) => lines(s).at(-1) ?? "";
const num = (s: string) => Number(last(s).trim());

console.log(`fresh clone: ${clone}`);
let r = sh(`git clone --quiet "${SRC}" "${clone}"`, tmp);
if (r.code !== 0) throw new Error(`clone failed: ${r.err}`);
const head = sh("git rev-parse --short HEAD").out.trim();
r = sh("bun install --frozen-lockfile");
if (r.code !== 0) throw new Error(`install failed: ${r.err}`);
console.log(`HEAD ${head}; installed with --frozen-lockfile`);
mkdirSync(join(clone, "out", "probe"), { recursive: true });

type Probe = { id: string; cmd: string; env?: Record<string, string>; pass: (r: R) => boolean; show?: (r: R) => string };
const P: Probe[] = [
  { id: "S16", cmd: "bun run demo; git status --porcelain | grep -v '^?? out/' | wc -l", pass: (r) => r.code === 0 && num(r.out) === 0 && r.ms < 90_000 && /^SIGNATURE: /m.test(r.out), show: (r) => `${(r.ms / 1000).toFixed(1)}s, ${(r.out.match(/^SIGNATURE: /gm) ?? []).length} SIGNATURE lines` },
  { id: "S1", cmd: `jq -r '."$schema", (.required|sort|join(","))' packages/schema/declaration.schema.json`, pass: (r) => r.code === 0 && /2020-12/.test(r.out) && ["id", "name", "owner", "risk_tier", "autonomy_level", "tools", "data_classes", "sandbox", "max_scopes", "kill_switch", "review_due", "control_mappings"].every((f) => last(r.out).split(",").includes(f)) },
  { id: "S2", cmd: `for f in packages/fixtures/declarations/*.yaml; do $CLI declare validate "$f" || exit 1; done; set +e; $CLI declare validate packages/fixtures/declarations/bad/missing-owner.yaml; echo "bad=$?"`, pass: (r) => r.code === 0 && /bad=1/.test(r.out) && /owner/.test(r.out + r.err) },
  { id: "S3", cmd: `$CLI record build packages/fixtures/declarations/evidence-reader.yaml --out out/probe/ && R=$(ls out/probe/*.record.json) && $CLI record verify "$R" && jq '.canonical_sha256="0000"' "$R" > out/probe/tampered.json; set +e; $CLI record verify out/probe/tampered.json; echo "tampered=$?"`, pass: (r) => r.code === 0 && /hashes ok/.test(r.out) && /tampered=1/.test(r.out) },
  { id: "S4", cmd: `set +e; a=0; for b in stale high-no-killswitch auth-unbounded; do $CLI record lint packages/fixtures/records/bad/$b.record.json; [ $? -eq 1 ] && a=$((a+1)); done; echo "bad-rejected=$a"; set -e; for r in $OUT/records/*.record.json; do $CLI record lint "$r" || exit 1; done`, pass: (r) => r.code === 0 && /bad-rejected=3/.test(r.out) },
  { id: "S5", cmd: `R=$(ls $OUT/records/*.record.json | head -1); $CLI record verify "$R" --pubkey $OUT/keys/cosign.pub && cp "$R" out/probe/unsigned.record.json; set +e; $CLI gate serve --record out/probe/unsigned.record.json --pubkey $OUT/keys/cosign.pub --self-test --upstream $CLI upstream demo; echo "gate=$?"`, pass: (r) => r.code === 0 && /signature ok/.test(r.out) && /gate=1/.test(r.out) && /signature/.test(r.err) },
  { id: "S6", cmd: `for f in packages/fixtures/gate-input/*.json; do echo "$(basename $f .json) $(opa eval -f raw -d packages/policy/gate.rego -i $f 'concat(":", [data.colophon.gate.decision.effect, concat(",", data.colophon.gate.decision.rule_ids)])')"; done`, pass: (r) => r.code === 0 && ["in-scope allow:COL-GATE-ALLOW", "unknown-tool deny:COL-GATE-UNKNOWN-TOOL", "scope-expansion deny:COL-GATE-SCOPE", "sandbox-escape deny:COL-GATE-SANDBOX", "data-class deny:COL-GATE-DATACLASS", "destination deny:COL-GATE-DESTINATION", "needs-approval escalate:COL-GATE-APPROVAL"].every((x) => r.out.includes(x)) },
  { id: "S7", cmd: `jq -c 'select(.effect=="deny") | select((.rule_ids|length)==0 or (.reasons|length)==0 or (.reasons[0].field|length)==0)' $OUT/*/trace/*.jsonl | wc -l`, pass: (r) => r.code === 0 && num(r.out) === 0 },
  { id: "S8", cmd: `opa test packages/policy -v 2>&1 | grep -c PASS; opa fmt --list packages/policy`, pass: (r) => r.code === 0 && Number(lines(r.out)[0]) >= 20 && lines(r.out).length === 1, show: (r) => `${lines(r.out)[0]} PASS lines` },
  { id: "S9", cmd: `bun tests/policy-flip.ts 2>/dev/null`, pass: (r) => r.code === 0 && /FLIP: sandbox-escape deny -> allow/.test(r.out) && /ts-diff: 0/.test(r.out) },
  { id: "S10", cmd: `$CLI agent run --scenario packages/fixtures/scenarios/evidence-reader.yaml --record $OUT/records/evidence-reader.record.json --pubkey $OUT/keys/cosign.pub --out out/probe/opa-fail 2>out/probe/opa-fail.err; jq -r '.effect+":"+.rule_ids[0]' out/probe/opa-fail/trace/*.jsonl | sort -u`, env: { COLOPHON_GATE_POLICY: "/nonexistent/gate.rego" }, pass: (r) => r.code === 0 && lines(r.out).filter((l) => l.includes(":")).join(",") === "deny:COL-GATE-OPA-ERROR" },
  { id: "S11", cmd: `grep -rnE '(allow|deny)' packages --include=*.ts | grep -vE 'effect|Decision|rule_ids|OPA-ERROR|test|type |import|//|\\*' | grep -E '(===|includes|startsWith|match)' | wc -l`, pass: (r) => num(r.out) === 0 },
  { id: "S12", cmd: `$CLI agent run --scenario packages/fixtures/scenarios/evidence-reader.yaml --record $OUT/records/evidence-reader.record.json --pubkey $OUT/keys/cosign.pub --out out/probe/mcp --list-tools 2>/dev/null; grep -c . out/probe/mcp/upstream-calls.jsonl; jq -r 'select(.effect=="deny").tool' out/probe/mcp/trace/*.jsonl | sort -u > out/probe/denied.txt; jq -r '.tool' out/probe/mcp/upstream-calls.jsonl | sort -u > out/probe/reached.txt; echo "overlap=$(comm -12 out/probe/denied.txt out/probe/reached.txt | wc -l | tr -d ' ')"`, pass: (r) => r.code === 0 && /tools: auth\.request_scopes, fs\.read, fs\.write, repo\.list, repo\.read_settings/.test(r.out) && /overlap=0/.test(r.out) },
  { id: "S13", cmd: `$CLI trace verify $OUT/evidence-reader/trace/*.jsonl`, pass: (r) => r.code === 0 && /schema: ok/.test(r.out) },
  { id: "S14", cmd: `cp $OUT/evidence-reader/trace/*.jsonl out/probe/t.jsonl; sed -i.bak '3s/deny/DENY/' out/probe/t.jsonl; set +e; $CLI trace verify out/probe/t.jsonl; echo "exit=$?"`, pass: (r) => /exit=1/.test(r.out) && /line 3/.test(r.err + r.out) },
  { id: "S15", cmd: `T=$(grep -o 'ghp_[A-Za-z0-9]*' packages/fixtures/scenarios/evidence-reader.yaml | head -1); grep -r "$T" out/demo | wc -l; grep -rl "$(printf %s "$T" | shasum -a 256 | cut -c1-64)" out/demo | wc -l`, pass: (r) => r.code === 0 && Number(lines(r.out)[0]) === 0 && Number(lines(r.out)[1]) >= 1, show: (r) => `literal ${lines(r.out)[0]} hits, hash ${lines(r.out)[1]} files` },
  { id: "S17", cmd: `jq -r 'select(.effect=="deny").rule_ids[]' $OUT/evidence-reader/trace/*.jsonl | sort -u; echo ---; jq -r 'select(.effect=="allow").tool' $OUT/notifier/trace/*.jsonl | sort -u; echo ---; jq -r 'select(.effect=="deny").rule_ids[]' $OUT/notifier/trace/*.jsonl | sort -u`, pass: (r) => { const s = r.out.split("---"); return r.code === 0 && ["COL-GATE-DATACLASS", "COL-GATE-SANDBOX", "COL-GATE-SCOPE", "COL-GATE-UNKNOWN-TOOL"].every((x) => s[0]!.includes(x)) && s[1]!.includes("fs.write") && s[1]!.includes("mail.send") && s[2]!.includes("COL-GATE-DESTINATION"); } },
  { id: "S18", cmd: `bun run demo >/dev/null && bun run demo >/dev/null && echo twice-ok`, pass: (r) => r.code === 0 && /twice-ok/.test(r.out) },
  { id: "S19", cmd: `set +e; bun run demo --out out/probe/signfail > out/probe/sf.out 2> out/probe/sf.err; echo "exit=$?"; echo "sig-lines=$(grep -c '^SIGNATURE:' out/probe/sf.out)"; echo "cosign-mentions=$(grep -ci cosign out/probe/sf.err)"; echo "bundles=$(ls out/probe/signfail/*/bundle/*.sigstore.json 2>/dev/null | wc -l | tr -d ' ')"`, env: { COLOPHON_COSIGN_BIN: "/bin/false" }, pass: (r) => /exit=1/.test(r.out) && /sig-lines=0/.test(r.out) && !/cosign-mentions=0/.test(r.out) && /bundles=0/.test(r.out) },
  { id: "S20", cmd: `bun test tests/evidence.test.ts 2>&1`, pass: (r) => r.code === 0 && /duplicate/.test(r.out) && /mismatch/.test(r.out) && /0 fail/.test(r.out) },
  { id: "S21", cmd: `bun tests/catalog-shape.ts`, pass: (r) => r.code === 0 && /themes: 8\/8/.test(r.out) && Number(/controls: (\d+)/.exec(r.out)?.[1]) >= 8 },
  { id: "S22", cmd: `$CLI report validate $OUT/evidence-reader/bundle/report/assessment-results.json`, pass: (r) => r.code === 0 && /oscal-version: 1\.2\.3/.test(r.out) },
  { id: "S23", cmd: `$CLI bundle verify $OUT/evidence-reader/bundle --pubkey $OUT/keys/cosign.pub`, pass: (r) => r.code === 0 && Number(/rlinks: (\d+) resolved/.exec(r.out)?.[1]) >= 1 && /unresolved: 0/.test(r.out) },
  { id: "S24", cmd: `bun test tests/citation.test.ts 2>&1`, pass: (r) => r.code === 0 && /refuses/.test(r.out) && /0 fail/.test(r.out) },
  { id: "S25", cmd: `grep -c 'Judgment is not' $OUT/evidence-reader/bundle/report/narrative.md; grep -ci 'does not prove' $OUT/evidence-reader/bundle/report/narrative.md; grep -ci vacuous $OUT/evidence-reader/bundle/report/narrative.md || true`, pass: (r) => { const n = lines(r.out).map(Number); return n[0]! >= 1 && n[1]! >= 1 && n[2] === 0; } },
  { id: "S26", cmd: `$CLI report --trace packages/fixtures/traces/breach.jsonl --record $OUT/records/evidence-reader.record.json --out out/probe/breach >/dev/null; jq '[."assessment-results".results[].findings[] | select(.target.status.state=="not-satisfied")] | length' out/probe/breach/report/assessment-results.json; jq -r '."assessment-results".results[].findings[] | select(.target.status.state=="not-satisfied") | .title' out/probe/breach/report/assessment-results.json`, pass: (r) => r.code === 0 && Number(lines(r.out)[0]) >= 1 && /COL-05/.test(r.out), show: (r) => lines(r.out).slice(1).join("; ") },
  { id: "S27", cmd: `jq -r '.root_sha256, (.files|length)' $OUT/evidence-reader/bundle/manifest.json; set +e; $CLI bundle create --from $OUT/evidence-reader/stage --out $OUT/evidence-reader/bundle; echo "again=$?"`, pass: (r) => /^[0-9a-f]{64}$/m.test(r.out) && Number(lines(r.out)[1]) >= 4 && /again=1/.test(r.out) },
  { id: "S28", cmd: `rm -rf out/probe/b out/probe/b2; cp -r $OUT/evidence-reader/bundle out/probe/b && printf x >> out/probe/b/report/narrative.md; set +e; $CLI bundle verify out/probe/b --pubkey $OUT/keys/cosign.pub; echo "tamper=$?"; cp -r $OUT/evidence-reader/bundle out/probe/b2 && touch out/probe/b2/extra.txt; $CLI bundle verify out/probe/b2 --pubkey $OUT/keys/cosign.pub; echo "extra=$?"`, pass: (r) => /tamper=1/.test(r.out) && /extra=1/.test(r.out) && /narrative\.md/.test(r.err) && /extra\.txt/.test(r.err) },
  { id: "S29", cmd: `ls $OUT/evidence-reader/bundle/manifest.sigstore.json && rm -rf out/probe/b3 && cp -r $OUT/evidence-reader/bundle out/probe/b3 && rm out/probe/b3/manifest.sigstore.json; set +e; $CLI bundle verify out/probe/b3 --pubkey $OUT/keys/cosign.pub; echo "missing=$?"`, pass: (r) => /manifest\.sigstore\.json$/m.test(r.out) && /missing=1/.test(r.out) && /manifest\.sigstore\.json missing/.test(r.err) },
  { id: "S30", cmd: `$CLI bundle verify $OUT/evidence-reader/bundle --pubkey $OUT/keys/cosign.pub --out out/probe/vr && $CLI report validate out/probe/vr/verification-results.json && jq -r '."assessment-results".results[].findings[].title' out/probe/vr/verification-results.json`, pass: (r) => r.code === 0 && /COL-08/.test(r.out) && /COL-09/.test(r.out) && /oscal-version: 1\.2\.3/.test(r.out) },
  { id: "S31", cmd: `$CLI normalize claude-hook packages/fixtures/claude-hook/session.jsonl --out out/probe/ch && $CLI trace verify out/probe/ch/trace/*.jsonl && jq -r '.source' out/probe/ch/trace/*.jsonl | sort -u && $CLI bundle verify $OUT/claude-hook/bundle --pubkey $OUT/keys/cosign.pub`, pass: (r) => r.code === 0 && /^claude-hook$/m.test(r.out) && /verified:/.test(r.out) },
  { id: "S32", cmd: `$CLI normalize aws-config packages/fixtures/aws --out out/probe/aws && jq -r '.effect' out/probe/aws/trace/*.jsonl | sort | uniq -c; echo "deps=$(jq -r '(.dependencies + .devDependencies)|keys[]' package.json | grep -c aws || true)"; echo "live=$(grep -rn 'LiveAws\\|@aws-sdk' packages | wc -l | tr -d ' ')"`, pass: (r) => r.code === 0 && /allow/.test(r.out) && /deny/.test(r.out) && /deps=0/.test(r.out) && /live=0/.test(r.out) },
  { id: "S33", cmd: `grep -c 'Custody is provable. Judgment is not.' README.md; grep -c 'bun install && bun run demo' README.md; grep -c 'bundle verify' README.md; grep -c 'STATUS.md' README.md`, pass: (r) => r.code === 0 && lines(r.out).every((l) => Number(l) >= 1) },
  { id: "S34", cmd: `grep -cE '^\\| (S[0-9]+|A[0-9]+) ' STATUS.md`, pass: (r) => num(r.out) === 40 },
  { id: "S35", cmd: `grep -ci 'operator brief' DECISIONS.md || true; grep -c '^### ' DECISIONS.md`, pass: (r) => Number(lines(r.out)[0]) === 0 && Number(lines(r.out)[1]) >= 8 },
  { id: "S36", cmd: `bun test tests 2>&1 | tail -3; bun run typecheck`, pass: (r) => r.code === 0 && /0 fail/.test(r.out) },
  { id: "S37", cmd: `grep -E 'cosign-installer|cosign-release|bun-version|frozen-lockfile|opa test|bun run demo|probes.ts|sigstore.json|bundle verify|certificate-identity' .github/workflows/ci.yml | wc -l`, pass: (r) => num(r.out) >= 9 },
  { id: "A1", cmd: `grep -rnE 'signed\\.ok|fallback|stopgap' packages --include=*.ts | wc -l`, pass: (r) => num(r.out) === 0 },
  { id: "A2", cmd: `jq -r '(.dependencies + .devDependencies)|keys[]' package.json | grep -ciE 'openai|anthropic|aws-sdk|google-ai|bedrock' || true`, pass: (r) => num(r.out) === 0 },
  { id: "A3", cmd: `gitleaks detect --no-git --config .gitleaks.toml --exit-code 1 -v 2>&1 | tail -2`, pass: (r) => r.code === 0 && /no leaks found/.test(r.out) },
];

const results: { id: string; pass: boolean; ms: number; detail: string }[] = [];
for (const p of P) {
  const r = sh(p.cmd, clone, p.env);
  const ok = p.pass(r);
  const detail = p.show ? p.show(r) : (last(r.out) || last(r.err)).slice(0, 100);
  results.push({ id: p.id, pass: ok, ms: r.ms, detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${p.id.padEnd(4)} ${(r.ms / 1000).toFixed(1).padStart(6)}s  ${detail}`);
  if (!ok) console.log(`     exit=${r.code}\n     stdout: ${r.out.trim().split("\n").slice(-6).join("\n             ")}\n     stderr: ${r.err.trim().split("\n").slice(-6).join("\n             ")}`);
}
const failed = results.filter((x) => !x.pass);
mkdirSync(join(SRC, "out"), { recursive: true });
writeFileSync(join(SRC, "out", "probes.json"), JSON.stringify({ head, ran_at: new Date().toISOString(), clone, results }, null, 2) + "\n");
console.log(`\n${results.length - failed.length}/${results.length} probes pass at HEAD ${head}${failed.length ? ` — FAILED: ${failed.map((f) => f.id).join(", ")}` : ""}`);
if (!KEEP) spawnSync("rm", ["-rf", tmp]);
process.exit(failed.length ? 1 : 0);
