/**
 * S11: no TypeScript verdicts. Scans every .ts under packages/ for an object
 * literal that names a gate effect. The only permitted literal is the deny in
 * the fail-closed wrapper (packages/gate/eval.ts, COL-GATE-OPA-ERROR).
 * Adapters translate a FOREIGN PEP's verdict field into an effect; they may
 * name "allow"/"deny" only when keyed on that foreign field, never on a tool
 * name, path, scope, or data class — checked by the second scan.
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { listFiles } from "../packages/bundle/manifest.ts";

const ROOT = resolve(import.meta.dir, "../packages");
const files = listFiles(ROOT).filter((p) => p.endsWith(".ts"));
const EFFECT_LITERAL = /effect\s*:\s*["'`](allow|escalate|deny)["'`]|["'](allow|deny|escalate)["']\s*:\s*["'](allow|deny|escalate)["']/;
const KEYED_ON_POLICY_FIELD = /(tool|name|path|scope|data_class|destination|url|to)\b[^;\n]{0,60}(===|!==|includes\(|startsWith\(|endsWith\(|match\()[^;\n]{0,80}(allow|deny|escalate)/;
const ALLOWED: Record<string, RegExp[]> = {
  "gate/eval.ts": [/effect: "deny", rule_ids: \["COL-GATE-OPA-ERROR"\]/],
  "adapters/claude-hook/index.ts": [/const EFFECTS: Record<string, Effect> = \{ allow: "allow", deny: "deny", ask: "escalate" \}/, /: "deny";$/],
  "adapters/aws-config/index.ts": [/effect: denied \? "deny" : "allow"/],
  "adapters/agentcore-dogwood/index.ts": [/const EFFECTS: Record<string, Effect> = \{ allow: "allow", deny: "deny", ALLOW: "allow", DENY: "deny" \}/, /: "deny";$/],
  // Assessment reads a recorded effect; it never produces one.
  "catalog/checks.ts": [/\.effect === "deny"/, /\.effect !== "allow"/],
};
let bad = 0;
for (const f of files) {
  const text = readFileSync(join(ROOT, f), "utf8");
  text.split("\n").forEach((line, i) => {
    const hit = EFFECT_LITERAL.test(line);
    const keyed = KEYED_ON_POLICY_FIELD.test(line);
    if (!hit && !keyed) return;
    const ok = (ALLOWED[f] ?? []).some((re) => re.test(line.trim()));
    if (!ok) {
      bad++;
      console.log(`VERDICT-IN-TS ${f}:${i + 1}: ${line.trim().slice(0, 120)}`);
    }
  });
}
console.log(`files scanned: ${files.length}`);
console.log(`verdict literals outside the fail-closed wrapper and foreign-field translations: ${bad}`);
process.exit(bad === 0 ? 0 : 1);
