import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { FindingDocument } from "./map.ts";

function fileName(sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 120);
  return `${safe || "session"}.finding.json`;
}

export type WrittenFinding = { path: string; finding: FindingDocument };

/** Write one JSON file per Finding. Does not write into a Cosign bundle. */
export function writeFindings(outDir: string, findings: FindingDocument[]): WrittenFinding[] {
  mkdirSync(outDir, { recursive: true });
  return findings.map((finding) => {
    const path = join(outDir, fileName(finding.resource.id));
    writeFileSync(path, JSON.stringify(finding, null, 2) + "\n");
    return { path, finding };
  });
}
