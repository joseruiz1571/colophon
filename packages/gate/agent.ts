/**
 * Scripted agent: an MCP client that replays a scenario through the gate.
 * The gate process wraps the upstream process; three processes, one pipe
 * each. Exit is 0 when the scenario completes regardless of how many calls
 * were refused; a refusal is a result, not a failure.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import YAML from "yaml";

export type Scenario = {
  name: string;
  agent: string;
  task: string;
  calls: { tool: string; arguments: Record<string, unknown> }[];
};

export type CallOutcome = { tool: string; refused: boolean; result: unknown };

export function loadScenario(path: string): Scenario {
  const s = YAML.parse(readFileSync(path, "utf8")) as Scenario;
  if (!s || typeof s.name !== "string" || !Array.isArray(s.calls)) throw new Error(`scenario malformed: ${path}`);
  return s;
}

export type RunOptions = {
  scenario: Scenario;
  recordPath: string;
  pubkeyPath: string;
  tracePath: string;
  sessionId: string;
  upstream: string[];
  upstreamLog: string;
  selfTestOut: string;
  listTools?: boolean;
  env?: Record<string, string>;
};

export async function runScenario(o: RunOptions): Promise<{ tools: string[]; outcomes: CallOutcome[] }> {
  const cli = resolve(import.meta.dir, "../cli/main.ts");
  const gateArgs = [cli, "gate", "serve", "--record", o.recordPath, "--pubkey", o.pubkeyPath, "--trace", o.tracePath, "--session", o.sessionId, "--self-test-out", o.selfTestOut, "--upstream", ...o.upstream];
  const client = new Client({ name: `agent-${o.scenario.agent}`, version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: gateArgs,
    env: { ...(process.env as Record<string, string>), ...(o.env ?? {}), COLOPHON_UPSTREAM_LOG: o.upstreamLog },
    stderr: "inherit",
  });
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map((t) => t.name).sort();
  if (o.listTools) process.stdout.write(`tools: ${tools.join(", ")}\n`);
  const outcomes: CallOutcome[] = [];
  for (const call of o.scenario.calls) {
    const res = (await client.callTool({ name: call.tool, arguments: call.arguments })) as { isError?: boolean; content?: { type: string; text?: string }[] };
    const textOut = res.content?.find((c) => c.type === "text")?.text ?? "";
    let parsed: unknown = textOut;
    try {
      parsed = JSON.parse(textOut);
    } catch {
      /* keep raw */
    }
    outcomes.push({ tool: call.tool, refused: res.isError === true, result: parsed });
  }
  await client.close();
  return { tools, outcomes };
}
