/**
 * Demo upstream: an MCP stdio server exposing synthetic tools over a fixture
 * tree. It touches no network and writes nothing except an append-only log of
 * the calls that reached it (COLOPHON_UPSTREAM_LOG), which is how a probe
 * proves a denied call never arrived.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import { redactArgs } from "../normalize/decision.ts";

const FIXTURE_ROOT = resolve(import.meta.dir, "../fixtures/upstream");

function log(tool: string, args: unknown): void {
  const path = process.env["COLOPHON_UPSTREAM_LOG"];
  if (!path) return;
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify({ ts: new Date().toISOString(), tool, args: redactArgs(args) }) + "\n");
}

function text(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

function fixture(rel: string): string {
  const full = resolve(FIXTURE_ROOT, rel);
  if (!full.startsWith(FIXTURE_ROOT + "/")) throw new Error(`path escapes fixture root: ${rel}`);
  if (!existsSync(full)) throw new Error(`fixture not found: ${rel}`);
  return readFileSync(full, "utf8");
}

export const DEMO_TOOLS = ["repo.list", "repo.read_settings", "fs.read", "fs.write", "auth.request_scopes", "mail.send", "net.fetch"] as const;

export async function serveUpstream(): Promise<void> {
  const server = new McpServer({ name: "colophon-demo-upstream", version: "0.1.0" });

  server.registerTool("repo.list", { description: "List repositories in an org (fixture).", inputSchema: { org: z.string(), data_class: z.string().optional() } }, async (a) => {
    log("repo.list", a);
    return text(JSON.parse(fixture(join("repos", a.org, "index.json"))));
  });
  server.registerTool("repo.read_settings", { description: "Read branch protection for a repo (fixture).", inputSchema: { repo: z.string(), data_class: z.string().optional() } }, async (a) => {
    log("repo.read_settings", a);
    const [org, name] = a.repo.split("/");
    return text(JSON.parse(fixture(join("repos", org ?? "", `${name ?? ""}.json`))));
  });
  server.registerTool("fs.read", { description: "Read a file from the fixture tree.", inputSchema: { path: z.string(), data_class: z.string().optional() } }, async (a) => {
    log("fs.read", a);
    return text({ path: a.path, content: fixture(a.path) });
  });
  server.registerTool("fs.write", { description: "Write a file (demo: recorded, not persisted).", inputSchema: { path: z.string(), content: z.string().optional(), data_class: z.string().optional(), token: z.string().optional() } }, async (a) => {
    log("fs.write", a);
    return text({ written: a.path, bytes: (a.content ?? "").length });
  });
  server.registerTool("auth.request_scopes", { description: "Request credential scopes (demo: recorded).", inputSchema: { scopes: z.array(z.string()) } }, async (a) => {
    log("auth.request_scopes", a);
    return text({ granted: a.scopes });
  });
  server.registerTool("mail.send", { description: "Send mail (demo: recorded, nothing sent).", inputSchema: { to: z.string(), subject: z.string(), body: z.string().optional() } }, async (a) => {
    log("mail.send", a);
    return text({ queued: true, to: a.to });
  });
  server.registerTool("net.fetch", { description: "Fetch a URL (demo: recorded, no network).", inputSchema: { url: z.string(), data_class: z.string().optional() } }, async (a) => {
    log("net.fetch", a);
    return text({ url: a.url, status: 200, body: "(fixture)" });
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  await new Promise<void>((done) => {
    transport.onclose = () => done();
  });
}
