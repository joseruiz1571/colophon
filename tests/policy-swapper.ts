// S64 test helper: alternates a policy file between two versions with atomic renames until killed.
import { renameSync, writeFileSync } from "node:fs";

const [target, a, b] = process.argv.slice(2) as [string, string, string];
const ta = await Bun.file(a).text();
const tb = await Bun.file(b).text();
for (let i = 0; ; i++) {
  const tmp = target + ".swap";
  writeFileSync(tmp, i % 2 ? ta : tb);
  renameSync(tmp, target);
  await Bun.sleep(1);
}
