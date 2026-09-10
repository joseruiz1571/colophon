import { loadCatalog } from "../packages/catalog/checks.ts";
const c = loadCatalog();
const themes: [string, RegExp][] = [
  ["declaration completeness", /declaration-complete/],
  ["gate fail-closed", /gate-fail-closed/],
  ["deny has rule + field", /deny-has-rule-and-field/],
  ["trace integrity", /trace-chain-intact/],
  ["citation guard", /citation-guard/],
  ["manifest completeness (verify)", /manifest-complete/],
  ["signature present (verify)", /signature-verifies/],
  ["narrative states limits", /narrative-states-limits/],
];
const checks = c.controls.map((x) => x.check);
let hit = 0;
for (const [name, re] of themes) {
  const found = c.controls.find((x) => re.test(x.check));
  if (found) hit++;
  console.log(`${found ? "ok  " : "MISS"} ${name}${found ? ` → ${found.id} (${found.phase})` : ""}`);
}
const bad = c.controls.filter((x) => !x.id || !x.title || !x.intent || !x.phase || !x.check || !x.falsifier || !x.framework_refs?.length);
const verifyPhase = c.controls.filter((x) => x.phase === "verify").map((x) => x.id);
console.log(`controls: ${c.controls.length}`);
console.log(`themes: ${hit}/${themes.length}`);
console.log(`verify-phase: ${verifyPhase.join(", ")}`);
console.log(`malformed: ${bad.length}`);
if (c.controls.length < 8 || hit < themes.length || bad.length > 0 || new Set(checks).size !== checks.length) process.exit(1);
