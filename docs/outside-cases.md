# Two outside cases: a leaked credential and a research design

> **Status: draft, not yet read by the maintainer.** Written by a coding agent on 2026-11-22 against the code at the commit that adds this file. The replay in section 1 is probed (S65, S66). The readings of the two sources are the agent's, and a reading can be wrong. Nobody outside this repository has reviewed them.

**Sources, as read on 2026-11-22:**

- Together AI, *Security event: Prompt leakage for requests in June and July of 2026*. The page reads "Published 11/21/2026". <https://www.together.ai/blog/security-event-prompt-leakage-for-requests-in-june-and-july-of-2026>
- V. K. Nguyen and M. I. Husain, *Agent Trust Infrastructure (ATI): A Federated Identity, Trust, Attestation, and Accountability Architecture for Cross-Organization Autonomous AI Agents*, arXiv:2611.23202v1, 17 Nov 2026. <https://arxiv.org/abs/2611.23202> The paper was read in full. Its code repository was not read.

**Subject:** the Colophon session packet, as specified in [`SPEC.md`](../SPEC.md), at this commit.

> **The one-line result.** Colophon would not have stopped the leak, and replaying the incident found a leak of Colophon's own, now fixed. ATI's log and Colophon's trace are close relatives. They differ in what each one records and in who can check it afterwards.

---

## 1. The incident: a coding agent commits a credential

### 1.1 What the disclosure says, and what it does not

In the company's words:

- Prompt samples collected for testing were "stored ... in a private Hugging Face repository."
- "During development of our public GitHub repository, xorl, an AI coding agent committed a credential that provided access to the private Hugging Face repository."
- "Our automated scanning detected the exposed credential, and we reverted the commit."
- During the exposure window "an unauthorized party obtained the credential and used it to download the stored prompt samples," then "searched those samples for credentials to other services and tested whether those credentials were valid."

The four changes it lists:

1. "Using scoped or short-lived credentials, and keyless access where supported"
2. "Checking all pull requests for credentials."
3. "Making zero data retention (ZDR) the default setting for new accounts."
4. "Updating our development processes governing the use of AI coding agents."

The disclosure does not name the agent, the kind of credential, or the length of the exposure window. It does not say whether a person approved the commit, or what record existed of the agent's session. So nothing below is a statement about what Together AI had or lacked. It is a statement about what a Colophon packet would hold if a session of the same shape ran under the Colophon hook.

### 1.2 The replay

A synthetic Claude Code session of that shape was run through the real hook, one process per call, against the shipped `claude-coder` Declaration (writes allowed under `src/`, `tests/` and `docs/`; every shell command handed to the human). The credential is a Hugging Face user token built at runtime. `tests/outside-cases.test.ts` repeats this on every probe run (S66).

| # | Call | Verdict | What the Decision holds |
| --- | --- | --- | --- |
| 1 | `Write` to `src/eval/loader.ts`; the content holds the token | allow (`COL-GATE-ALLOW`) | the path, the operator's data class, and `claude.tool_input_sha256`, a hash of the whole tool input. None of the content. |
| 2 | `Bash`: `git add -A && git commit -m "add eval loader"` | ask (`COL-GATE-APPROVAL`) | the command text |
| 3 | `Bash`: `git push origin main` | ask (`COL-GATE-APPROVAL`) | the command text |

The sealed packet verifies. COL-03 reads not-satisfied, because no refusal occurred and a control that was not exercised is not reported as passing (D12). COL-10 reads satisfied, and no file in the packet holds the token.

### 1.3 What the packet would show, and what it would not

| Would show | Would not show |
| --- | --- |
| Which signed Declaration was in force, and that it allowed writes under `src/` and handed every shell command to a person. | That the file content held a credential. The gate reads the path of a write. It does not read the content. |
| The order of the calls (the write, then the commit, then the push), unedited since the packet was sealed. | What the person answered when asked about the commit and the push. The hook records the question and not the answer ([`claude-code.md`](claude-code.md); Proof-of-Control 4.1.6, not met). |
| A hash of the write's whole input. Given the file afterwards, anyone can recompute that hash and show that this call wrote those bytes. | What the shell commands did. An `ask` is not evidence that the commit or the push ran. |
| Which policy text decided each call (`policy_sha256`). | Anything at all, if the hook was off or the agent ran somewhere else. |

**Colophon would not have stopped the leak.** No rule in `gate.rego` reads the content of a write, and the write was inside the declared sandbox. The control that caught the credential in the disclosure was a scanner, and the second change on the company's list is more scanning. That is the right control for the content of a commit.

What a packet adds is narrower. After the fact, it ties the leak to one call, in one session, under one signed set of rules, and it shows that the commit and the push were put to a person. It also bears on the fourth change. A process rule for coding agents is a Declaration, and a packet is how someone outside the team checks that the rule was in force for a given session. That is custody. It is not prevention.

### 1.4 What the replay found in Colophon

The first form of the replay also passed the token inline in a shell command (`HF_TOKEN=<token> bun run eval`). The command was sealed into the trace with the token in clear, the packet signed, and COL-10 reported "no credential-shaped value is present."

The cause is that redaction and COL-10 share one pattern (D30), and the pattern is a list of known shapes. Hugging Face tokens were not on it. A custody tool that copies a live credential into a signed, portable packet makes an incident like this one worse, and SPEC section 2 says no credential value appears in a packet.

Fixed here (S65, D39): the pattern covers the two Hugging Face shapes that gitleaks 8.30.1 detects, a user access token and an organization API token.

The limit that remains is the class, and it is stated rather than fixed. A credential in a shape that is not on the list still passes both redaction and COL-10. One general remedy, not built and for the maintainer to decide: commit the value of any assignment to a secret-named variable inside a string, the way secret-named JSON keys are committed already. COL-10 would then have to tell a commitment from a survivor.

### 1.5 What would change the answer

- **A content rule.** A write whose content matches the credential pattern could be denied or put to a person. Verdicts come only from Rego (S11), so the hook would pass the policy a flag and never the content. Not built.
- **The other half of the record.** A PostToolUse hook would record what the person chose and whether the call ran. Not built ([`claude-code.md`](claude-code.md)).

Neither would make the hook a secret scanner. Scanning every pull request stays the control for that.

---

## 2. The research design: Agent Trust Infrastructure

### 2.1 What the paper proposes

ATI is a reference monitor with five planes that sits outside the agent framework. Identity, Trust and Attestation check a request before the agent's model runs. Policy checks each tool call. Accountability "records every allowed action in a signed, hash-chained log that ties an action to the acting identity and model."

In a simulated federation of eight organizations the paper reports attack containment rising from 43% to 84% across 14 attack cases, at about 174 microseconds per request. The authors state the limits of the simulation plainly: it "runs the federation in a single process," the monitor and its planes "are about 350 lines of Python," and the attack runs used one pair of frameworks.

### 2.2 Plane by plane

| ATI plane | What it does, per the paper | Colophon |
| --- | --- | --- |
| Identity | Each agent holds an Ed25519 key. Its identifier (AID) is the hash of the public key, and each request is signed. | None. A Decision carries `session_id` and `record_sha256`, and the Record names the agent and its owner. There is no key per agent and no principal per action ([`proof-of-control.md`](proof-of-control.md), 5.1.1). |
| Trust | Each organization runs its own certificate authority. Peers trust each other with no root above them. Certificates are checked for issuer, expiry, name constraint and revocation. | None. One signer per packet: a Cosign key, or the CI workflow's identity. Nothing federates. |
| Attestation | The running model, the pinned tool and a hash of the system prompt are compared with the approved values before the model is called. | None. A Declaration has no field for the model or the system prompt. What the Record binds is the declared tools, scopes, paths and data classes, signed and checked again on every hook call. |
| Policy | Three rules, in code, at each tool call: no write to another organization, no replayed transaction, no bulk read from a sensitive office. | `gate.rego` through OPA on every call: unknown tool, scope, sandbox, data class, destination, approval, stale Record. The policy text is hashed into each Decision and staged in the packet (S48). |
| Accountability | An append-only log with one signed entry per allowed action. | The Trace: one Decision per call, hash-chained, signed once per packet. |

### 2.3 Entry by entry

The paper's log entry (its Fig. 6 and section V-E) beside a Colophon Decision:

| ATI log entry | Colophon Decision |
| --- | --- |
| time | `ts` |
| AID, the acting agent | no equivalent; `session_id` and `record_sha256` are the nearest |
| model | no equivalent |
| organization, agent | the Record's `owner` and `name`, reached through `record_sha256` |
| tool | `tool` |
| SHA-256 of the arguments | `args_sha256`, with a redacted view in `args_redacted` |
| hash of the previous entry | `prev_sha256` |
| signature over the entry, with the organization's CA key | none per Decision; one Cosign signature over the manifest |
| not in the entry | `effect`, `rule_ids`, `reasons` naming the Record field, `policy_sha256`, `call_index` |

### 2.4 Where each is ahead

**ATI is ahead in four places.**

- It signs every entry when the action happens. Colophon signs once, at seal, and the trace is chained but unsigned until then (README, "Where this sits"; Proof-of-Control 7.1.2, not met).
- Each entry names the acting agent and the model.
- It checks the model, the tool and the system prompt before the agent runs. Colophon checks none of the three.
- It has an answer for trust between organizations. Colophon has one signer and one verifier.

**Colophon is ahead in four places.**

- It records refusals and escalations, each with its rule and the Record field that bound it. The paper's log holds allowed actions: the Accountability plane "blocks nothing," and when a check fails "nothing is written" at the receiving organization (section V-F). For an assessor, a refusal is where a control shows that it works (COL-03).
- It detects a trace cut short at the end. The paper says "Deleting entries from the end is not caught, because nothing records how long the chain should be." Colophon's head commitment records the line count and the last hash (S13, D20).
- It binds each verdict to the policy text that produced it, and the text travels in the packet (S48, S49).
- The record leaves the building. A stranger verifies a packet with `cosign` and the directory, and the control findings are OSCAL Assessment Results with a stated falsifier for each control.

**Both share three limits.**

- The party that runs the monitor holds the signing key. The paper says its log gives tamper-evident records "under the assumption that signing keys remain secure, rather than unconditional non-repudiation." Colophon's own grade is Tier 2 for the same reason ([`proof-of-control.md`](proof-of-control.md)).
- Neither records what the tool did or returned. The paper says hashes of the prompt, the reasoning and the output "would fit in the same entry but are not captured yet." A Colophon Decision is written before the call is forwarded.
- Neither design measures the host. The paper's attestation checks are "simple comparisons and hashes done in the same process, not signed reports," and they run "once, when a request first enters the federation, not on a timer." Colophon makes no attestation claim at all.

### 2.5 What ATI would have done with the incident

Its threat model is a request that crosses from one organization to another. The incident is one agent, inside one organization's own repository, writing a secret into a file.

Attestation asks whether the approved model, tool and prompt are running. An approved agent in its approved setup can still write a credential into a file. The Policy plane's three rules do not read the content of a write either. The Accountability plane would hold an entry for the call with a hash of its arguments, much as Colophon's trace does.

So neither design stops this incident, and both leave a record of it.

---

## 3. What the two cases show together

Three different questions are in play, and each case answers a different one.

| Question | ATI | Colophon | What the incident needed |
| --- | --- | --- | --- |
| Was the approved agent running? | yes: Attestation, before the model runs | no | not the failure, as far as the disclosure says |
| What did the agent do, in what order, under which rules? | allowed actions, signed per entry | every decision, refusals included, signed per packet | useful afterwards |
| Was the content of the action safe? | no | no | yes: this is what the scanner caught |

Attesting a configuration and recording an action are both worth having, and neither is a check on what the action carries. The honest place for Colophon in an incident like this one is the second row.
