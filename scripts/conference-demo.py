#!/usr/bin/env python3
"""Regenerate the offline demo from repository fixtures; Python standard library only."""
import argparse
import html
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--mlassure', type=Path, required=True, help='Installed companion checkout (no API key needed)')
a = p.parse_args()
ML = a.mlassure.resolve()
os.chdir(ROOT)

def run(cmd, cwd=ROOT, expected=0):
    result = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != expected:
        raise RuntimeError(f'{shlex.join(cmd)}: expected exit {expected}, got {result.returncode}\n{result.stdout}')
    return result.stdout.strip()

def read(path):
    return Path(path).read_text()

def dump(value):
    return json.dumps(value, indent=2, ensure_ascii=False)

for tool in ('bun', 'opa', 'cosign'):
    if not shutil.which(tool):
        p.error(f'{tool} must be installed; see .github/workflows/ci.yml for pinned versions')
(ROOT / 'out').mkdir(exist_ok=True)
# The existing demo removes its output directory. Give it a new, dedicated directory.
work = Path(tempfile.mkdtemp(prefix='conference-', dir=ROOT / 'out'))
demo = work / 'demo'
print('Running existing demo with disposable keys and fixtures…', flush=True)
run(['bun', 'run', 'demo', '--out', str(demo)])
bundle = demo / 'notifier/bundle'
key = demo / 'keys/cosign.pub'
verify = ['bun', 'packages/cli/main.ts', 'bundle', 'verify']
success = run(verify + [str(bundle), '--pubkey', str(key)])
cosign = ['cosign', 'verify-blob', '--key', str(key), '--bundle', str(bundle / 'manifest.sigstore.json'), '--insecure-ignore-tlog', str(bundle / 'manifest.json')]
signature = run(cosign)
tampered = work / 'tampered'
shutil.copytree(bundle, tampered)
trace = next((tampered / 'trace').glob('*.jsonl'))
original = read(trace)
assert 'ops@evil.example' in original
trace.write_text(original.replace('ops@evil.example', 'ops@acme.example'))
failure = run(verify + [str(tampered), '--pubkey', str(key)], expected=1)
assert 'this_sha256 mismatch' in failure and 'FAIL manifest:' in failure and 'sha256 mismatch' in failure
# The manifest was not changed: its signature should still pass.
still_signed = run([s.replace(str(bundle), str(tampered)) for s in cosign])
mlcmd = ['bun', 'run', 'dev', '--', 'verify-bundle']
positive = 'fixtures/bundles/positive/fraud-detection-v2-clean'
negative = 'fixtures/bundles/negative/tampered-file'
mlpass = run(mlcmd + [positive], cwd=ML)
mlfail = run(mlcmd + [negative], cwd=ML, expected=1)
guard = run(['bun', 'test', 'src/guard/citation-guard.test.ts'], cwd=ML)
assert '0 fail' in guard
trace_original = next((bundle / 'trace').glob('*.jsonl'))
decisions = [json.loads(line) for line in read(trace_original).splitlines()]
decision = next(d for d in decisions if 'COL-GATE-DESTINATION' in d['rule_ids'])
assert decision['effect'] == 'deny' and decision['args_redacted']['to'] == 'ops@evil.example'
assert decision['prev_sha256'] == decisions[1]['this_sha256']
upstream = [json.loads(line) for line in read(demo / 'notifier/upstream-calls.jsonl').splitlines()]
assert len(upstream) == 2 and all(c['args'].get('to') != 'ops@evil.example' for c in upstream)
policy = read(ROOT / 'packages/policy/gate.rego')
rule = policy[policy.index('denies contains {"rule_id": "COL-GATE-DESTINATION"'):policy.index('\ndenies contains', policy.index('denies contains {"rule_id": "COL-GATE-DESTINATION"') + 1)]
declaration = read(ROOT / 'packages/fixtures/declarations/notifier.yaml')
report = json.loads(read(ML / positive / 'report.json'))
judgment = report['results'][0]['judgment']
sha = run(['git', 'rev-parse', 'HEAD'])
mlsha = run(['git', 'rev-parse', 'HEAD'], cwd=ML)
date = datetime.now(timezone.utc).isoformat(timespec='seconds')
# Only paths are shortened in displayed output; hashes and verdicts stay verbatim.
def display(text):
    return text.replace(str(work), '$RUN')

sections = []
def section(title, lead, body, details):
    sections.append((title, lead, body, details))
section('The boundary', 'Authorized: *@acme.example. Attempted: ops@evil.example. Denied.',
    'The notifier fixture calls mail.send through Colophon’s reference MCP gate. OPA evaluates gate.rego against the signed Record; this call is refused before the demo upstream executes it. No real email is sent.',
    [('Declaration · exact fixture', declaration), ('Rego · exact destination rule excerpt', rule),
     ('Enforcement scope', 'This is the reference Rego gate. Foreign PEPs such as AgentCore Gateway + Dogwood enforce their own policies; Colophon normalizes and seals their decisions. LOG_ONLY records a would-be verdict and does not establish that a call was blocked. This build uses repository fixtures, not a fresh AWS session.')])
section('The evidence', 'A refusal carries its rule, its bound inputs, and a link to the previous decision.',
    'record_sha256 binds the decision to the Record’s canonical_sha256. policy_sha256 binds it to the gate.rego bytes. prev_sha256 equals the previous decision’s this_sha256. this_sha256 hashes this decision (excluding itself). The signed bundle also covers the trace head’s line count and final hash, so truncation is detectable.',
    [('Actual decision · full fields and hashes', dump(decision)), ('Actual trace head', read(str(trace_original) + '.head.json')),
     ('Chain limits', 'The chain commits to recorded order. It does not independently establish real-world timing or prove that every action was recorded. Before sealing, the chain is not signed; a writer could rebuild it. The signature anchors the sealed packet to a key.')])
section('The verification', 'The original passes. An edited trace fails. The unchanged manifest still has a valid signature.',
    'Cosign checks manifest.json. Colophon also checks the listed files, Record signature, policy binding, OSCAL evidence links, and trace chain. The altered copy replaces ops@evil.example with ops@acme.example in the trace without re-signing.',
    [('Actual notifier bundle · complete file list', '\n'.join(str(f.relative_to(bundle)) for f in sorted(bundle.rglob('*')) if f.is_file())),
     ('Cosign · exit 0', display(signature)), ('Colophon · exit 0', display(success)),
     ('Tampered copy · Colophon exit 1', display(failure)), ('Tampered copy · Cosign still exits 0', display(still_signed)),
     ('Trust boundary', 'The local demo uses a disposable key and no transparency-log entry, hence --insecure-ignore-tlog. A recipient must obtain a trusted public key independently; accepting a key supplied by an unknown producer proves no trusted identity. The HTML is a rendering, not a signed packet.')])
section('The complementary project', 'mlassure asks whether collected evidence supports a control assessment.',
    'Deterministic collectors retrieve fixture evidence into an EvidenceStore. Control pattern tags select code checks, LLM judgment, or human-attestation handling. The citation guard rejects IDs absent from the current store; satisfied and partially-satisfied verdicts must cite evidence. Existing citations establish traceability, not relevance or sound reasoning. The live AWS provider is deferred in this revision.',
    [('Recorded assessment · exact conformance-fixture judgment, not a fresh LLM run', dump(judgment)),
     ('Control examples from fixtures/controls/nist-subset.yaml', 'SC-28: deterministic encryption-at-rest check; no LLM call.\nSI-6(1): synthesis of monitoring evidence; LLM judgment.\nSA-10: human review; returns insufficient-evidence without an LLM call.'),
     ('Fresh check during generation · citation-guard tests', guard),
     ('Fresh check during generation · positive fixture, exit 0', mlpass),
     ('Fresh check during generation · tampered fixture, exit 1', mlfail),
     ('Independent bundle verification', 'mlassure bundles report.json, evidence/<uuid>.json (all retrieved payloads, cited or not), optional oscal.json and narrative.md, and manifest.json. verify-bundle checks integrity and completeness. Authenticity needs a separate Cosign check over the manifest. These checked-in conformance fixtures are unsigned; no fresh LLM assessment or mlassure signature verification is claimed. The projects are complementary; no automatic Colophon-to-mlassure integration is demonstrated.')])
section('What this proves', 'Evaluations tell us what happened. Verifiable evidence lets someone else check the claim.',
    'Keep four claims separate. A valid signature can accompany a mistaken assessment.',
    [('Evidence integrity', 'Manifest hashes and signatures bind the supplied bytes to a key. They do not establish that the evidence is true, complete relative to the outside world, or produced by a trustworthy operator.'),
     ('Policy enforcement', 'This notifier run exercises the reference gate’s destination refusal. A sealed foreign verdict records what that PEP reported; enforcement depends on that PEP, its mode, and whether the action passed through it.'),
     ('Control assessment', 'A finding applies a particular check or judgment to available evidence. The citation invariant excludes nonexistent evidence IDs; it cannot establish that the evidence supports the conclusion.'),
     ('Behavioral correctness', 'Neither project proves the agent is correct, safe in every context, or unable to bypass an unobserved boundary. Those claims require additional evaluation and coverage evidence.')])

reproduce = '''# Prerequisites: Python 3, Bun, OPA, Cosign 3.x (pins in .github/workflows/ci.yml).
# Install only existing locked dependencies in both checkouts:
(cd ../mlassure && bun install --frozen-lockfile)
bun install --frozen-lockfile
python3 scripts/conference-demo.py --mlassure ../mlassure

# Each run prints its own $RUN directory under ignored out/conference-*.
# Substitute that path below. It contains a disposable private key: do not publish it.
RUN=out/conference-REPLACE_WITH_PRINTED_RUN
B="$RUN/demo/notifier/bundle"
cosign verify-blob --key "$RUN/demo/keys/cosign.pub" \\
  --bundle "$B/manifest.sigstore.json" --insecure-ignore-tlog "$B/manifest.json"
bun packages/cli/main.ts bundle verify "$B" --pubkey "$RUN/demo/keys/cosign.pub"
bun packages/cli/main.ts bundle verify "$RUN/tampered" --pubkey "$RUN/demo/keys/cosign.pub"
# Last command must exit 1. The generator checks this and the named failure reasons.
'''
provenance = f'Generated {date}. Colophon source {sha}; mlassure source {mlsha}. Executed during generation, recorded when viewed. Paths shortened to $RUN; output otherwise preserved. Sessions, keys, timestamps and hashes vary on regeneration. Only synthetic fixture content is embedded.'
versions = '\n'.join([run(['bun', '--version']), run(['opa', 'version']), run(['cosign', 'version'])])
versions = '\n'.join(line.rstrip() for line in versions.splitlines())
sources = [('Colophon walkthrough', f'https://github.com/joseruiz1571/colophon/blob/{sha}/docs/walkthrough.md'), ('Reference policy', f'https://github.com/joseruiz1571/colophon/blob/{sha}/packages/policy/gate.rego'), ('mlassure bundle spec', f'https://github.com/joseruiz1571/mlassure/blob/{mlsha}/SPEC.md'), ('mlassure conformance vectors', f'https://github.com/joseruiz1571/mlassure/blob/{mlsha}/fixtures/bundles/README.md'), ('mlassure citation guard', f'https://github.com/joseruiz1571/mlassure/blob/{mlsha}/src/guard/citation-guard.ts')]
e = html.escape
cards = []
for i, (title, lead, body, details) in enumerate(sections, 1):
    expanded = ''.join(f'<details><summary>{e(label)}</summary><pre>{e(value)}</pre></details>' for label, value in details)
    if i == 5:
        expanded = ''.join(f'<div class="claim"><h3>{e(label)}</h3><p>{e(value)}</p></div>' for label, value in details)
    cards.append(f'<section id="s{i}" aria-labelledby="h{i}"><span class="eyebrow">0{i} / 05 · {e(title)}</span><h2 id="h{i}">{e(lead)}</h2><p>{e(body)}</p>{expanded}<a class="next" href="#s{i+1 if i<5 else 1}">{"Next →" if i<5 else "Back to the boundary ↑"}</a></section>')
css = '''*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:5rem}body{margin:0;background:#101a22;color:#edf4f3;font:17px/1.6 system-ui,sans-serif}header,main,footer{max-width:850px;margin:auto;padding:1.25rem}header{padding-top:2.5rem}h1{font-size:clamp(2rem,6vw,3.6rem);line-height:1.07;letter-spacing:-.04em;margin:.7rem 0}h2{font-size:clamp(1.45rem,4vw,2.1rem);line-height:1.25}h3{font-size:1rem;color:#8ee1c5;margin-bottom:0}p{color:#cbd8df}.eyebrow{color:#8ee1c5;font-size:.78rem;font-weight:750;letter-spacing:.09em;text-transform:uppercase}nav{position:sticky;top:0;background:#101a22f5;z-index:1;border-block:1px solid #344651;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.1rem;padding:.4rem;max-width:850px;margin:auto}a{color:#8ee1c5;text-underline-offset:4px}nav a{padding:.65rem .15rem;font-size:.85rem;text-decoration:none;text-align:center}section{border:1px solid #344651;border-radius:18px;padding:clamp(1rem,4vw,2rem);margin:1.2rem 0 2rem;background:#172630;scroll-margin-top:1rem}details{border-top:1px solid #3b4e59;padding:.65rem 0}summary{cursor:pointer;min-height:44px;display:list-item;padding:.5rem 0;font-size:.95rem;font-weight:650}pre{background:#0b141b;color:#d9e8ed;padding:1rem;border-radius:8px;font:12px/1.6 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:2}a:focus-visible,summary:focus-visible{outline:3px solid #ffc879;outline-offset:3px}.next{display:inline-block;padding:.8rem 0;margin-top:.6rem}.note{border-left:3px solid #ffc879;padding-left:1rem;font-size:.9rem}.claim{border-top:1px solid #344651}.claim p{margin-top:.3rem}footer{font-size:.85rem;overflow-wrap:anywhere}@media(max-width:380px){nav a{padding:.6rem .1rem;font-size:.75rem}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}@media print{nav,.next{display:none}body,section{background:white;color:black}p,pre,h3,.eyebrow{color:black}section{break-inside:avoid}}'''
page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Colophon + mlassure · Evidence someone else can check</title><style>{css}</style></head><body>
<header><span class="eyebrow">[un]prompted · Colophon + mlassure</span><h1>Evidence someone else can check.</h1><p><strong>15 seconds:</strong> An agent tries to mail outside its declared scope. The gate refuses it. A signed packet lets someone else check the refusal’s recorded evidence. mlassure applies the same discipline to control assessments.</p><p class="note"><strong>Two minutes:</strong> follow the five screens; tap a detail to inspect source or output. Fully offline. All verification below is recorded from generation, not run by this page.</p></header>
<nav aria-label="Demo screens">{''.join(f'<a href="#s{i}">{i} {label}</a>' for i,label in enumerate(['Boundary','Evidence','Verify','mlassure','Limits'],1))}</nav><main>{''.join(cards)}</main>
<footer><h2>Reproduce & inspect</h2><p>{e(provenance)}</p><details><summary>Regeneration and verification commands</summary><pre>{e(reproduce)}</pre></details><details><summary>Tool versions used</summary><pre>{e(versions)}</pre></details><p>Source links require a network; all demo content above is embedded.</p><ul>{''.join(f'<li><a href="{url}">{e(label)}</a></li>' for label,url in sources)}</ul></footer></body></html>'''
(ROOT / 'docs/conference-demo.html').write_text(page)
# The concise alternative retains the actual decision and core verification lines.
md = ['# Colophon + mlassure at [un]prompted', 'Recorded from fresh local fixture verification during generation; opening this document does not run a verifier. [Offline HTML with expandable details](conference-demo.html).', '**15 seconds:** An agent tries to mail outside its declared scope. The gate refuses it. A signed packet lets someone else check the recorded evidence. mlassure brings evidence traceability to control assessments.', '> Evaluations tell us what happened. Verifiable evidence lets someone else check the claim.', '## 1 — The boundary', sections[0][2], '```yaml\n' + declaration[declaration.index('  - name: mail.send'):declaration.index('\ndata_classes: [internal]')] + '\n```', '```rego\n' + rule + '\n```', sections[0][3][-1][1], '## 2 — The evidence', sections[1][2], '```json\n' + dump(decision) + '\n```', sections[1][3][-1][1], '## 3 — The verification', sections[2][1], sections[2][2], 'Actual bundle paths (complete):\n```text\n' + sections[2][3][0][1] + '\n```']
for label, output in [('Cosign exit 0', signature), ('Colophon exit 0 (selected lines)', '\n'.join(l for l in success.splitlines() if l.startswith(('record:', 'policy:', 'trace:', 'verified:')))), ('Tampered copy exit 1 (selected lines)', '\n'.join(l for l in failure.splitlines() if 'mismatch' in l or 'NOT VERIFIED' in l))]:
    md += [label + ':\n```text\n' + display(output) + '\n```']
md += [sections[2][3][-1][1], '## 4 — The complementary project', sections[3][2], 'Recorded conformance fixture (not a fresh LLM assessment):\n```json\n' + dump(judgment) + '\n```', sections[3][3][1][1], 'During generation, the citation-guard suite passed; the positive custody fixture passed and the tampered-file fixture failed. Full output is embedded in the HTML.', sections[3][3][-1][1], '## 5 — What this proves']
md += [f'**{label}:** {value}' for label,value in sections[4][3]]
md += ['## Reproduce', provenance, '```sh\n' + reproduce + '```', '\n'.join(f'- [{label}]({url})' for label,url in sources)]
(ROOT / 'docs/conference-demo.md').write_text('\n\n'.join(md).replace('evidence/<uuid>.json', '`evidence/<uuid>.json`') + '\n')
print(f'Wrote docs/conference-demo.html and .md. Verification artifacts: {work.relative_to(ROOT)}')
