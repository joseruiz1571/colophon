# Contributing

Done means a probe passed from a fresh clone. That is the whole workflow.

## Setup

Bun ≥ 1.4 (the lockfile is version 2), OPA ≥ 1.0, Cosign 3.x, jq. CI pins exact versions in `.github/workflows/ci.yml`; match them if something differs locally.

```
bun install --frozen-lockfile
bun run typecheck && bun test tests && opa test packages/policy -v
bun run demo
```

## Making a change

1. Add or change the claim in `SPEC.md` first, with a literal shell probe and a pass condition. If it cannot be probed, it is not a claim.
2. Add the probe to `tests/probes.ts` with the same id.
3. Build until the probe passes.
4. Commit, then run `bun tests/probes.ts`. It clones committed HEAD into a temp directory and runs every probe there; uncommitted work is invisible on purpose.
5. Regenerate `STATUS.md` with `bun tests/write-status.ts` and commit it. The HEAD it cites is the commit before it.
6. Record any judgment call in `DECISIONS.md` with the rationale.

## Rules that do not bend

- Verdicts come only from `packages/policy/gate.rego`. `tests/no-ts-verdicts.ts` fails the build if TypeScript decides.
- Nothing in tests, demo, or CI touches the network except `bun install` and, in CI only, Sigstore keyless signing.
- No fixture value may be shaped like a real credential; build test tokens at runtime (see `tests/trace.test.ts`).
- Paths inside a packet are relative. A packet is portable evidence.
- `bun` and `bunx` only. Never npm.

## Agent-built changes

Much of this repository was written by coding agents against `SPEC.md` and graded by the probe suite. That is fine and it is the method. Own it in the commit: the author field says who typed, `DECISIONS.md` says who decided, and the probe says whether it is true.
