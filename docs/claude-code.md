# Colophon for Claude Code

Declare it, run it, seal it, hand it to a stranger. This page is the whole loop on your own laptop with a tool you already use.

## What you get

A Claude Code session where every tool call was decided by your signed Declaration before it ran, a hash-chained trace of those decisions, and at the end a packet a stranger verifies with `cosign` alone. The hook is the policy enforcement point; `gate.rego` through OPA is the only thing that decides; the hook rewrites nothing.

## Prerequisites

`bun` ≥ 1.4, `opa`, `cosign` 3.x. A cosign key pair (the demo's throwaway pair under `out/demo/keys` works for a trial; use your own for anything you will hand to someone).

## 1. Declare

Copy `packages/fixtures/declarations/claude-coder.yaml` and edit it. The parts that matter for a coding session:

```yaml
tools:
  - name: fs.read      # Read, Glob, Grep
    data_access: read
    data_classes: [public, internal]
  - name: fs.write     # Write, Edit, MultiEdit, NotebookEdit
    data_access: write
    data_classes: [internal]
  - name: shell.exec   # Bash
    data_access: none
    data_classes: []
    requires_approval: true          # every Bash becomes "ask"
  - name: net.fetch    # WebFetch
    data_access: none
    data_classes: []
    destinations: ["https://docs.acme.example/*"]
sandbox:
  write_paths: ["src/", "tests/", "docs/"]   # relative to the session's cwd
defaults:
  data_class: internal               # the label Claude Code never sends
```

Tool names are Colophon's projections of Claude Code's: `Write` → `fs.write`, `Bash` → `shell.exec`, `WebFetch` → `net.fetch`, `WebSearch` → `net.search`, `mcp__server__tool` → `mcp.server.tool`. Anything not declared is refused (`COL-GATE-UNKNOWN-TOOL`). Paths inside the session's working directory are relativized before the sandbox check, so `write_paths` is written once and the signed Record holds on any machine; a path outside cwd stays absolute and no relative prefix admits it.

## 2. Build and sign the Record

```
bun packages/cli/main.ts record build my-coder.yaml --out out/hook
bun packages/cli/main.ts record sign out/hook/my-coder.record.json --key path/to/cosign.key
bun packages/cli/main.ts record verify out/hook/my-coder.record.json --pubkey path/to/cosign.pub
```

## 3. Install the hook

```
bun packages/cli/main.ts hook settings --record out/hook/my-coder.record.json --pubkey path/to/cosign.pub --trace-dir out/hook/trace
```

Paste the printed fragment into the project's `.claude/settings.json` (or `.claude/settings.local.json`). It registers one PreToolUse hook with an empty matcher, so every tool call passes through it, with a 30 second timeout. Paths in that fragment are absolute on purpose: it is machine config, not a packet.

## 4. Work

Use Claude Code normally. On each tool call the hook binds the Record (hash, signature, lint), decides, appends one line to `out/hook/trace/<session_id>.jsonl`, and answers:

| gate effect | Claude Code sees | what happens |
|---|---|---|
| `allow` | `allow` | the call runs without a prompt |
| `deny` | `deny` + `[RULE-ID] field: value` | the call is cancelled; Claude reads the reason and adjusts |
| `escalate` | `ask` | the normal permission prompt; the human decides |

Cost is about half a second per call on a laptop (measured: eight calls in 3.7 s), most of it process start-up plus two OPA evaluations; `cosign verify-blob` itself is under 0.1 s. The first call of a session also runs the fail-closed self-test and writes `<session_id>.selftest.json` beside the trace.

## 5. Seal

```
bun packages/cli/main.ts seal --session <session_id> --trace-dir out/hook/trace \
  --record out/hook/my-coder.record.json --pubkey path/to/cosign.pub \
  --key path/to/cosign.key --out out/hook/packets
```

The session id is in the trace filename. `seal` assesses the catalog over the trace, writes the OSCAL Assessment Results and the narrative, bundles, signs, verifies, and only then prints `SIGNATURE:`.

## 6. Hand it over

```
cosign verify-blob --key path/to/cosign.pub \
  --bundle out/hook/packets/<session_id>/bundle/manifest.sigstore.json \
  --insecure-ignore-tlog out/hook/packets/<session_id>/bundle/manifest.json
bun packages/cli/main.ts bundle verify out/hook/packets/<session_id>/bundle --pubkey path/to/cosign.pub
```

The first command needs only cosign. The second walks manifest → signature → OSCAL rlinks → files → hashes → trace chain → Record binding.

## What this proves, and what it does not

Proves: which Declaration was in force (signed, bound on every call); what each call was projected to and how it was decided, in order, unedited since; that refusals cite the rule and the Record field; that the self-test denied an undeclared tool and a broken policy engine on this machine at session start.

Does not prove: what a shell command did (the gate cannot parse shell, so `shell.exec` is bounded only by `requires_approval`; a Bash `printf > /tmp/x` is an `ask`, not a sandbox check, and the first live session showed exactly that); what the human chose when asked (the hook sees the question, not the answer; a PostToolUse hook would); that the Declaration was the right policy; the content of files (`data_class` is the operator's label from `defaults`, recorded as such); that a call bypassed hooks entirely (a disabled hook records nothing, which the packet cannot show). Custody is provable. Judgment is not.

## Fail closed

Malformed stdin, a Record whose signature does not verify, and an OPA failure all answer `deny` under `COL-GATE-OPA-ERROR`, and the deny is appended to the trace whenever a session id was present. Deleting or rotating the Record's signature is the kill switch: every subsequent call is refused.

## Try it without Claude Code

`bun run demo` already does this: it pipes `packages/fixtures/claude-hook/events.jsonl` through the real `hook` command one process per event, seals the session, and verifies the `claude-coder` packet. `bun tests/probes.ts` runs S44–S47 from a fresh clone.
