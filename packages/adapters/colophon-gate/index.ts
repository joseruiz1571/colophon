/** Reference adapter: the gate already writes Decisions; this reads and re-verifies them. */
import { readTrace, verifyTrace } from "../../trace/trace.ts";
import type { Decision } from "../../normalize/decision.ts";

export const SOURCE = "colophon-gate";

export function readGateDecisions(tracePath: string): Decision[] {
  const v = verifyTrace(tracePath);
  if (!v.ok) throw new Error(`gate trace rejected: ${v.reason}`);
  const decisions = readTrace(tracePath);
  const foreign = decisions.find((d) => d.source !== SOURCE);
  if (foreign) throw new Error(`gate trace contains a decision from ${foreign.source}`);
  return decisions;
}
