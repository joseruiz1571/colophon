/**
 * `colophon view`: one static HTML page for one packet.
 *
 * The page is a rendering, not evidence. It runs the same verification a
 * stranger would (`verifyBundle`) and then shows only two kinds of thing:
 * the verifier's own lines, and content read from files the manifest hashes
 * (trace, Record, session, assessment results, narrative). It adds no claim
 * of its own: no verdict, no control state, no limit is decided here.
 *
 * Fails closed: if the verifier reports any failure, the page shows the
 * failures and withholds the packet's content.
 *
 * The page carries no script and loads nothing. Styling keys on data
 * attributes whose values come from the packet, so this file names no effect
 * (S11) and no control state.
 */
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { hashFile, MANIFEST, type Manifest } from "../bundle/manifest.ts";
import { verifyBundle, type VerifyBundleOptions } from "../bundle/verify.ts";
import { bindingReasons, type Decision } from "../normalize/decision.ts";
import { primaryArg } from "../report/narrative.ts";
import { sha256Hex } from "../schema/canonical.ts";
import type { ColophonRecord } from "../schema/record.ts";

export type ViewOptions = Omit<VerifyBundleOptions, "out">;

export type ViewControl = { id: string; title: string; objective: string; state: string; rationale: string; falsifier: string };
export type ViewRecord = { file: string; name: string; owner: string; riskTier: string; autonomy: string; reviewDue: string; tools: string[]; sha256: string };
export type ViewPacket = {
  source: string;
  sessionId: string;
  task: string;
  rootSha256: string;
  files: number;
  records: ViewRecord[];
  policies: { path: string; sha256: string }[];
  traces: { file: string; decisions: Decision[] }[];
  controls: ViewControl[];
  limits: { rows: [string, string][]; closing: string };
};
export type ViewModel = {
  ok: boolean;
  /** Last two path segments of the bundle directory; never an absolute path. */
  bundleName: string;
  /** What the verifier was given to check the signature with, in words. */
  keyNote: string;
  verifyCommand: string;
  lines: string[];
  failures: string[];
  /** Present only when the verifier reported no failure. */
  packet: ViewPacket | null;
};

const LIMITS_HEADING = "## What this packet proves, and what it does not";

/** The proves / does-not-prove rows and the closing sentence, taken verbatim from the signed narrative. */
export function limitsFromNarrative(md: string): ViewPacket["limits"] {
  const at = md.indexOf(LIMITS_HEADING);
  if (at < 0) return { rows: [], closing: "" };
  const rows: [string, string][] = [];
  let closing = "";
  for (const line of md.slice(at + LIMITS_HEADING.length).split("\n")) {
    if (line.startsWith("## ")) break;
    if (line.startsWith("|")) {
      const cells = line.split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim().replace(/\\\|/g, "|"));
      if (cells.length === 2 && !/^-+$/.test(cells[0]!) && cells[0] !== "proves") rows.push([cells[0]!, cells[1]!]);
    } else if (line.trim() && !closing) closing = line.trim();
  }
  return { rows, closing };
}

type Finding = { description?: string; props?: { name: string; value: string }[]; target?: { title?: string; description?: string; status?: { state?: string } } };

function controlsFromAr(text: string): ViewControl[] {
  const doc = JSON.parse(text) as { "assessment-results": { results: { findings?: Finding[] }[] } };
  const out: ViewControl[] = [];
  for (const result of doc["assessment-results"].results) {
    for (const f of result.findings ?? []) {
      const prop = (n: string) => f.props?.find((p) => p.name === n)?.value ?? "";
      out.push({ id: prop("control-id"), title: f.target?.title ?? "", objective: f.target?.description ?? "", state: f.target?.status?.state ?? "", rationale: f.description ?? "", falsifier: prop("falsifier") });
    }
  }
  return out;
}

/**
 * Reads the packet's content for display. Every file is read once and its
 * bytes are checked against the manifest entry before use, so what the page
 * shows is what the manifest hashes, not whatever sits at the path after the
 * verifier has finished. `manifestSha256` is the manifest's hash taken before
 * verification; a manifest that changed since then is refused.
 */
export function readPacket(dir: string, manifestSha256: string): ViewPacket {
  const manifestBytes = readFileSync(join(dir, MANIFEST));
  if (sha256Hex(manifestBytes) !== manifestSha256) throw new Error(`${MANIFEST} changed while it was being verified`);
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as Manifest;
  const listed = new Map(manifest.files.map((f) => [f.path, f.sha256]));
  const read = (rel: string): string => {
    const bytes = readFileSync(join(dir, rel));
    if (sha256Hex(bytes) !== listed.get(rel)) throw new Error(`${rel} does not match its manifest entry`);
    return bytes.toString("utf8");
  };
  const under = (prefix: string, suffix = ""): string[] => [...listed.keys()].filter((p) => p.startsWith(prefix) && p.endsWith(suffix)).sort();
  const session = (listed.has("session.json") ? JSON.parse(read("session.json")) : {}) as { source?: string; session_id?: string; task?: string };
  const records: ViewRecord[] = under("records/", ".record.json").map((f) => {
    const r = JSON.parse(read(f)) as ColophonRecord;
    const d = r.declaration;
    return { file: f, name: d.name, owner: d.owner, riskTier: d.risk_tier, autonomy: d.autonomy_level, reviewDue: d.review_due, tools: d.tools.map((t) => t.name), sha256: r.canonical_sha256 };
  });
  const traces: ViewPacket["traces"] = under("trace/", ".jsonl").map((f) => ({ file: f, decisions: read(f).split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l) as Decision) }));
  return {
    source: session.source ?? "",
    sessionId: session.session_id ?? "",
    task: session.task ?? "",
    rootSha256: manifest.root_sha256,
    files: manifest.files.length,
    records,
    policies: under("policy/").map((f) => ({ path: f, sha256: listed.get(f)! })),
    traces,
    controls: controlsFromAr(read("report/assessment-results.json")),
    limits: limitsFromNarrative(listed.has("report/narrative.md") ? read("report/narrative.md") : ""),
  };
}

export function buildViewModel(o: ViewOptions): ViewModel {
  // The verifier is given absolute paths, so its lines name the bundle and key one way however the command was typed.
  const abs = resolve(o.dir);
  const key = o.pubkey ? resolve(o.pubkey) : undefined;
  const bundleName = join(basename(dirname(abs)), basename(abs));
  const keyName = key ? basename(key) : "";
  // The page reads the same on every machine: the bundle and key are named, never located. Only whole absolute paths are replaced, longest first.
  const swaps = ([[abs, bundleName], ...(key ? [[key, keyName]] : []), [process.cwd() + sep, ""], [homedir(), "~"]] as [string, string][]).sort((a, b) => b[0].length - a[0].length);
  const scrub = (s: string): string => swaps.reduce((t, [from, to]) => t.split(from).join(to), s);
  const manifestPath = join(abs, MANIFEST);
  const manifestSha256 = existsSync(manifestPath) ? sha256Hex(readFileSync(manifestPath)) : "";
  const v = verifyBundle({ ...o, dir: abs, pubkey: key });
  const keyNote = key
    ? existsSync(key)
      ? `public key ${keyName} (sha256 ${hashFile(key).sha256})`
      : `public key ${keyName} (file not found)`
    : o.certIdentityRegexp && o.oidcIssuer
      ? `certificate identity ${o.certIdentityRegexp} issued by ${o.oidcIssuer}`
      : "no verification material";
  const verifyCommand = key ? `colophon bundle verify ${bundleName} --pubkey ${keyName}` : `colophon bundle verify ${bundleName} --certificate-identity-regexp <re> --oidc-issuer <url>`;
  const failures = [...v.failures];
  let packet: ViewPacket | null = null;
  if (v.ok) {
    // A packet that verified but cannot be read back as verified is a failure like any other: it gets the NOT VERIFIED page, not a stack trace.
    try {
      packet = readPacket(abs, manifestSha256);
    } catch (e) {
      failures.push(`view: ${(e as Error).message}`);
    }
  }
  return { ok: failures.length === 0, bundleName, keyNote, verifyCommand, lines: v.lines.map(scrub), failures: failures.map(scrub), packet };
}

// ---------- rendering ----------

export function esc(v: unknown): string {
  return String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
/** Escape first, then turn the narrative's backtick spans into code. */
const inline = (s: string): string => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const short = (h: string): string => (h.length > 16 ? `${h.slice(0, 12)}…` : h);

function tally(values: string[]): string {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts].map(([k, n]) => `${n} ${esc(k)}`).join(" · ");
}

/** Packet-making order. Each step shows the verifier's own lines for it, verbatim. */
const STEPS: { prefix: string; label: string; plain: string }[] = [
  { prefix: "record:", label: "The promise", plain: "Checks the signed Record: what the operator declared the agent may do." },
  { prefix: "policy:", label: "The rule", plain: "Checks that the policy text behind the verdicts is in the packet, matched by hash." },
  { prefix: "trace:", label: "The decisions", plain: "Checks the hash chain over the tool-call verdicts, in order." },
  { prefix: "oscal:", label: "The evidence", plain: "Checks that each control finding's citations resolve to hashed files in the packet." },
  { prefix: "manifest:", label: "Nothing changed", plain: "Checks every file against the manifest: nothing added, removed, or altered." },
  { prefix: "signature:", label: "The seal", plain: "Checks the signature over the manifest with the material named above." },
];

function chainSection(lines: string[]): string {
  const items = STEPS.map((s) => {
    const own = lines.filter((l) => l.startsWith(s.prefix));
    // No colour and no tag of our own: a line the verifier printed is not always good news (a trace with no policy binding prints one too).
    const body = own.length ? own.map((l) => `<p class="vline">${esc(l)}</p>`).join("") : `<p class="vline none">The verifier printed nothing for this step.</p>`;
    return `<li data-step="${own.length ? "reported" : "silent"}"><div class="step-head"><b>${esc(s.label)}</b></div><p class="plain">${esc(s.plain)}</p>${body}</li>`;
  });
  return `<section><h2>The chain, link by link</h2><p class="note">Each link shows what <code>colophon bundle verify</code> printed for it, word for word.</p><ol class="chain">${items.join("")}</ol></section>`;
}

function decisionRows(decisions: Decision[]): string {
  return decisions
    .map((d) => {
      const r0 = bindingReasons(d)[0] ?? d.reasons[0];
      return `<tr><td>${esc(d.call_index ?? "")}</td><td><code>${esc(d.tool)}</code> ${esc(primaryArg(d))}</td><td><span class="effect" data-effect="${esc(d.effect)}">${esc(d.effect)}</span></td><td>${d.rule_ids.map((r) => `<code>${esc(r)}</code>`).join(" ")}</td><td>${r0 ? `<code>${esc(r0.field)}</code> ${esc(JSON.stringify(r0.value ?? ""))}` : ""}</td><td class="ts">${esc(d.ts)}</td></tr>`;
    })
    .join("");
}

function packetSections(m: ViewModel, p: ViewPacket): string {
  const all = p.traces.flatMap((t) => t.decisions);
  const out: string[] = [];
  out.push(`<section><h2>What was asked</h2><p>${esc(p.task) || "<span class=\"none\">No task text in session.json.</span>"}</p><p class="note">From <code>session.json</code>, written by the packet's builder.</p></section>`);
  out.push(chainSection(m.lines));
  if (p.records.length) {
    out.push(`<section><h2>The promise, in detail</h2>${p.records.map((r) => `<dl class="kv"><dt>Record</dt><dd><code>${esc(r.name)}</code> <span class="hash">sha256 ${esc(r.sha256)}</span></dd><dt>Owner</dt><dd>${esc(r.owner)}</dd><dt>Risk tier</dt><dd>${esc(r.riskTier)}</dd><dt>Autonomy</dt><dd>${esc(r.autonomy)}</dd><dt>Declared tools</dt><dd>${r.tools.map((t) => `<code>${esc(t)}</code>`).join(" ")}</dd><dt>Review due</dt><dd>${esc(r.reviewDue)}</dd></dl>`).join("")}</section>`);
  }
  if (p.policies.length) {
    out.push(`<section><h2>The rule, in detail</h2><ul class="files">${p.policies.map((f) => `<li><code>${esc(f.path)}</code> <span class="hash">sha256 ${esc(f.sha256)}</span></li>`).join("")}</ul></section>`);
  }
  out.push(`<section><h2>The decisions</h2><p>${all.length} tool calls: ${tally(all.map((d) => d.effect))}.</p>${p.traces.map((t) => `<p class="note"><code>${esc(t.file)}</code></p><div class="scroll"><table><thead><tr><th>#</th><th>Tool call</th><th>Effect</th><th>Rule</th><th>Bound by</th><th>Time</th></tr></thead><tbody>${decisionRows(t.decisions)}</tbody></table></div>`).join("")}</section>`);
  out.push(`<section><h2>Control findings</h2><p>${p.controls.length} controls: ${tally(p.controls.map((c) => c.state))}.</p><p class="note">States and rationales are read from the signed <code>report/assessment-results.json</code>. They were computed when the packet was built, not by this page.</p><div class="scroll"><table><thead><tr><th>Control</th><th>State</th><th>Why</th><th>What would falsify it</th></tr></thead><tbody>${p.controls.map((c) => `<tr><td><code>${esc(c.id)}</code><br>${esc(c.title)}</td><td><span class="state" data-state="${esc(c.state)}">${esc(c.state)}</span></td><td>${esc(c.rationale)}</td><td>${esc(c.falsifier)}</td></tr>`).join("")}</tbody></table></div></section>`);
  out.push(`<section><h2>What this packet proves, and what it does not</h2>${p.limits.rows.length ? `<div class="scroll"><table class="limits"><thead><tr><th>Proves</th><th>Does not prove</th></tr></thead><tbody>${p.limits.rows.map(([a, b]) => `<tr><td>${inline(a)}</td><td>${inline(b)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="none">The narrative in this packet has no proves / does-not-prove table.</p>`}${p.limits.closing ? `<p>${inline(p.limits.closing)}</p>` : ""}<p class="note">Copied from the signed <code>report/narrative.md</code>.</p></section>`);
  return out.join("\n");
}

const CSS = readFileSync(join(import.meta.dir, "view.css"), "utf8");

export function renderView(m: ViewModel): string {
  const p = m.packet;
  const title = m.ok && p ? `Colophon packet ${p.sessionId}` : `Colophon packet NOT VERIFIED`;
  const verdict = m.ok && p
    ? `<div class="verdict" data-verified="yes"><b>Verified</b><span>${p.traces.reduce((n, t) => n + t.decisions.length, 0)} decisions · ${p.controls.length} controls · ${p.files} files · source <code>${esc(p.source)}</code></span></div>`
    : `<div class="verdict" data-verified="no"><b>NOT VERIFIED</b><span>${m.failures.length} failure${m.failures.length === 1 ? "" : "s"}. The packet's contents are not shown.</span></div>`;
  const facts = `<dl class="kv"><dt>Bundle</dt><dd><code>${esc(m.bundleName)}</code></dd>${p ? `<dt>Session</dt><dd><code>${esc(p.sessionId)}</code></dd><dt>Manifest root</dt><dd><span class="hash">sha256 ${esc(p.rootSha256)}</span></dd>` : ""}<dt>Checked with</dt><dd>${esc(m.keyNote)}</dd></dl>`;
  const failed = m.ok
    ? ""
    : `<section><h2>What the verifier reported</h2><ul class="fail">${m.failures.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>${m.lines.length ? `<p class="note">Other lines the verifier printed. They describe files this run could not vouch for:</p><ul class="passed">${m.lines.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : ""}<p>A packet that does not verify is not evidence of anything. This page shows none of its decisions or findings.</p></section>`;
  const disclaimer = `<footer><p><b>This page is a rendering, not evidence.</b> Anyone can edit an HTML file. To check it, run the command below against your own copy of the bundle${p ? ` and compare the manifest root (${esc(short(p.rootSha256))})` : ""}.</p><pre>${esc(m.verifyCommand)}</pre><p class="note">Custody is provable. Judgment is not.</p></footer>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(title)}</title>
<style>
${CSS}</style>
</head>
<body>
<main>
<header><p class="eyebrow">Colophon session packet</p><h1>${esc(p ? p.sessionId : m.bundleName)}</h1>${verdict}${facts}</header>
${failed}${m.ok && p ? packetSections(m, p) : ""}
${disclaimer}
</main>
</body>
</html>
`;
}

/** The real location a path will have: the nearest ancestor that exists, resolved through symlinks and the filesystem's own spelling, plus the part not yet created. */
function realTarget(p: string): string {
  let head = resolve(p);
  const tail: string[] = [];
  while (!existsSync(head) && dirname(head) !== head) {
    tail.unshift(basename(head));
    head = dirname(head);
  }
  return join(realpathSync.native(head), ...tail);
}

/** True when `out` would land inside the bundle, which would add an unlisted file and break the manifest. Compared by real location, so a symlink or a differently-cased spelling of the bundle does not get past it. */
export function outInsideBundle(dir: string, out: string): boolean {
  return (realTarget(out) + sep).startsWith(realTarget(dir) + sep);
}
