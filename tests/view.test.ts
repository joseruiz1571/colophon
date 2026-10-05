/**
 * `colophon view`: the page mirrors the packet, fails closed, and is inert.
 * The end-to-end tests seal a real hook session with a throwaway cosign key,
 * exactly as hook.test.ts does, then render it. Every assertion compares the
 * page with what the packet or the verifier says; the page has no opinions
 * of its own to test.
 */
import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeyPair, offlineSigningConfig, signBlobWithKey } from "../packages/bundle/sign.ts";
import { verifyBundle } from "../packages/bundle/verify.ts";
import { recordSignaturePath } from "../packages/gate/server.ts";
import { runHook, sealSession } from "../packages/hook/index.ts";
import { buildRecord, loadDeclaration } from "../packages/schema/record.ts";
import { readTrace } from "../packages/trace/trace.ts";
import { buildViewModel, esc, limitsFromNarrative, outInsideBundle, renderView, type ViewModel } from "../packages/view/index.ts";

const FIX = resolve(import.meta.dir, "../packages/fixtures");
const CLI = resolve(import.meta.dir, "../packages/cli/main.ts");

const dir = mkdtempSync(join(tmpdir(), "colophon-view-"));
const keys = generateKeyPair(join(dir, "keys"), "test");
const recordPath = join(dir, "claude-coder.record.json");
writeFileSync(recordPath, JSON.stringify(buildRecord(loadDeclaration(join(FIX, "declarations", "claude-coder.yaml"))), null, 2) + "\n");
signBlobWithKey({ blob: recordPath, key: keys.key, password: "test", out: recordSignaturePath(recordPath), signingConfig: offlineSigningConfig(join(dir, "keys")) });
const traceDir = join(dir, "hook");
for (const line of readFileSync(join(FIX, "claude-hook", "events.jsonl"), "utf8").split("\n").filter(Boolean)) runHook(line, { recordPath, pubkeyPath: keys.pub, traceDir });
const packet = sealSession({ sessionId: "cc-live-0001", traceDir, recordPath, pubkeyPath: keys.pub, outRoot: join(dir, "packets"), signer: { mode: "key", key: keys.key, pub: keys.pub, password: "test", signingConfig: offlineSigningConfig(join(dir, "keys")) } });
const bundle = packet.bundleDir;
const model = buildViewModel({ dir: bundle, pubkey: keys.pub });
const page = renderView(model);

/** Everything after the stylesheet: the stylesheet names effects and states as selectors, the body only carries the packet's. */
const body = (html: string): string => html.split("</style>")[1]!;
const attrs = (html: string, name: string): string[] => [...body(html).matchAll(new RegExp(`${name}="([^"]*)"`, "g"))].map((m) => m[1]!);

describe("the page mirrors the packet", () => {
  const decisions = readTrace(join(bundle, "trace", "cc-live-0001.jsonl"));
  test("verified, and every decision appears once, in trace order, with its tool, effect and rule ids", () => {
    expect(model.ok).toBe(true);
    expect(page).toContain("<b>Verified</b>");
    expect(attrs(page, "data-effect")).toEqual(decisions.map((d) => d.effect));
    const rows = page.split("<tbody>")[1]!.split("</tbody>")[0]!.split("<tr>").slice(1);
    expect(rows.length).toBe(decisions.length);
    decisions.forEach((d, i) => {
      expect(rows[i]).toContain(`<td>${d.call_index}</td>`);
      expect(rows[i]).toContain(`<code>${esc(d.tool)}</code>`);
      for (const r of d.rule_ids) expect(rows[i]).toContain(`<code>${r}</code>`);
      expect(rows[i]).toContain(esc(d.ts));
    });
  });
  test("every control id and state equals the signed assessment results", () => {
    const ar = JSON.parse(readFileSync(join(bundle, "report", "assessment-results.json"), "utf8"));
    const findings = ar["assessment-results"].results.flatMap((r: { findings: unknown[] }) => r.findings) as { props: { name: string; value: string }[]; target: { status: { state: string } } }[];
    expect(findings.length).toBeGreaterThan(0);
    expect(attrs(page, "data-state")).toEqual(findings.map((f) => f.target.status.state));
    for (const f of findings) expect(page).toContain(`<code>${f.props.find((p) => p.name === "control-id")!.value}</code>`);
  });
  test("manifest root, record hash and the verifier's own lines are on the page", () => {
    const root = JSON.parse(readFileSync(join(bundle, "manifest.json"), "utf8")).root_sha256;
    expect(page).toContain(root);
    expect(page).toContain(packet.results.length ? "Control findings" : "");
    const v = verifyBundle({ dir: bundle, pubkey: keys.pub });
    expect(v.lines.length).toBeGreaterThanOrEqual(5);
    for (const l of model.lines) expect(page).toContain(esc(l));
    expect(model.lines.length).toBe(v.lines.length);
  });
  test("the limits table is the signed narrative's, row for row", () => {
    const limits = limitsFromNarrative(readFileSync(join(bundle, "report", "narrative.md"), "utf8"));
    expect(limits.rows.length).toBeGreaterThanOrEqual(6);
    expect(model.packet!.limits).toEqual(limits);
    expect(limits.rows[0]![1]).toBe("That the signer is trustworthy or authorized.");
    expect(limits.closing).toMatch(/^Custody is provable\. Judgment is not\./);
    expect(page).toContain("That every action the agent took passed through this PEP.");
  });
  test("the page says it is a rendering and gives the verify command", () => {
    expect(page).toContain("This page is a rendering, not evidence.");
    expect(page).toContain(`colophon bundle verify ${model.bundleName} --pubkey cosign.pub`);
  });
});

describe("fails closed", () => {
  const trace = (b: string) => join(b, "trace", "cc-live-0001.jsonl");
  const tampers: Record<string, (b: string) => void> = {
    "flip an effect": (b) => writeFileSync(trace(b), readFileSync(trace(b), "utf8").replace('"effect":"deny"', '"effect":"allow"')),
    "delete a decision": (b) => writeFileSync(trace(b), readFileSync(trace(b), "utf8").split("\n").filter((_, i) => i !== 5).join("\n")),
    "edit the policy": (b) => writeFileSync(join(b, "policy", "gate.rego"), readFileSync(join(b, "policy", "gate.rego"), "utf8") + "\n# edited\n"),
    "truncate the trace": (b) => writeFileSync(trace(b), readFileSync(trace(b), "utf8").trimEnd().split("\n").slice(0, -1).join("\n") + "\n"),
  };
  const refused = (m: ViewModel, html: string) => {
    expect(m.ok).toBe(false);
    expect(m.packet).toBeNull();
    expect(m.failures.length).toBeGreaterThan(0);
    expect(html).toContain("NOT VERIFIED");
    expect(html).not.toContain("<b>Verified</b>");
    expect(body(html)).not.toContain("data-effect=");
    expect(body(html)).not.toContain("data-state=");
    expect(body(html)).not.toContain("<table");
    for (const f of m.failures) expect(html).toContain(esc(f));
  };
  for (const [name, tamper] of Object.entries(tampers)) {
    test(`${name} → NOT VERIFIED, no decisions, no findings`, () => {
      const copy = join(mkdtempSync(join(tmpdir(), "colophon-view-t-")), "bundle");
      cpSync(bundle, copy, { recursive: true });
      tamper(copy);
      const m = buildViewModel({ dir: copy, pubkey: keys.pub });
      refused(m, renderView(m));
    });
  }
  test("no verification material → NOT VERIFIED", () => {
    const m = buildViewModel({ dir: bundle });
    refused(m, renderView(m));
    expect(m.keyNote).toBe("no verification material");
  });
  test("a different key → NOT VERIFIED", () => {
    const other = generateKeyPair(join(mkdtempSync(join(tmpdir(), "colophon-view-k-")), "keys"), "test");
    const m = buildViewModel({ dir: bundle, pubkey: other.pub });
    refused(m, renderView(m));
  });
  test("CLI: exit 1 and a page on failure; exit 0 on success; refuses to write inside the bundle", () => {
    const run = (args: string[]) => spawnSync(process.execPath, [CLI, "view", ...args], { encoding: "utf8" });
    const good = run([bundle, "--pubkey", keys.pub, "--out", join(dir, "good.html")]);
    expect(good.status).toBe(0);
    expect(readFileSync(join(dir, "good.html"), "utf8")).toBe(page);
    const bad = run([bundle, "--out", join(dir, "bad.html")]);
    expect(bad.status).toBe(1);
    expect(readFileSync(join(dir, "bad.html"), "utf8")).toContain("NOT VERIFIED");
    const inside = run([bundle, "--pubkey", keys.pub, "--out", join(bundle, "view.html")]);
    expect(inside.status).toBe(1);
    expect(inside.stderr).toContain("refusing to write inside the bundle");
    expect(verifyBundle({ dir: bundle, pubkey: keys.pub }).ok).toBe(true);
    expect(outInsideBundle(bundle, join(bundle, "..", "view.html"))).toBe(false);
    expect(outInsideBundle(bundle, bundle + "-view.html")).toBe(false);
  });
});

describe("inert, self-contained, and the same on every machine", () => {
  test("no script, no handler, nothing loaded, CSP locked", () => {
    expect(page).toContain(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`);
    expect(page).not.toMatch(/<script|<link|<img|<iframe|<object|<embed|<form|<a\s|javascript:|\ssrc=|\shref=|\son[a-z]+=|@import|url\(/i);
    expect(page.match(/<style>/g)!.length).toBe(1);
  });
  test("hostile packet strings are escaped everywhere they are rendered", () => {
    const x = `"><script>alert(1)</script><img src=x onerror=alert(1)>`;
    const hostile: ViewModel = {
      ok: true,
      bundleName: x,
      keyNote: x,
      verifyCommand: x,
      lines: [`trace: ${x}`, `record: ${x}`],
      failures: [],
      packet: {
        source: x,
        sessionId: x,
        task: x,
        rootSha256: x,
        files: 1,
        records: [{ file: x, name: x, owner: x, riskTier: x, autonomy: x, reviewDue: x, tools: [x], sha256: x }],
        policies: [{ path: x, sha256: x }],
        traces: [{ file: x, decisions: [{ source: x, effect: x as never, rule_ids: [x], reasons: [{ field: x, value: x }], tool: x, args_sha256: "0", args_redacted: { path: x }, call_index: 0, ts: x, prev_sha256: null, this_sha256: "0" }] }],
        controls: [{ id: x, title: x, objective: x, state: x, rationale: x, falsifier: x }],
        limits: { rows: [[`\`${x}\``, x]], closing: x },
      },
    };
    for (const m of [hostile, { ...hostile, ok: false, failures: [x], packet: null }]) {
      const html = renderView(m);
      expect(html).not.toContain("<script>alert");
      expect(html).not.toContain("<img");
      expect(html).not.toMatch(/"><script|onerror=alert\(1\)>/);
      expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    }
  });
  test("byte-identical across runs and across relative or absolute invocation; no machine paths", () => {
    expect(renderView(buildViewModel({ dir: bundle, pubkey: keys.pub }))).toBe(page);
    expect(page).not.toContain(dir);
    expect(page).not.toContain(tmpdir());
    expect(page).not.toContain(homedir());
    expect(model.bundleName).toBe(join(packet.name, "bundle"));
  });
});
