# Show: the live packet in four commands

AgentCore/Dogwood enforce; this directory is the portable receipt.

```
bun install && bun run demo
bun packages/cli/main.ts bundle verify out/demo/agentcore-dogwood-live/bundle --pubkey out/demo/keys/cosign.pub
cosign verify-blob --key out/demo/keys/cosign.pub --bundle out/demo/agentcore-dogwood-live/bundle/manifest.sigstore.json --insecure-ignore-tlog out/demo/agentcore-dogwood-live/bundle/manifest.json
(cd out/demo/agentcore-dogwood-live/bundle && jq -r '.files[] | "\(.sha256)  \(.path)"' manifest.json | shasum -a 256 -c --quiet && echo "ALL FILES MATCH")
```

The third command is what a stranger with only `cosign` runs: it proves the manifest bytes are unchanged since the key signed them. It checks `manifest.json` alone. The fourth is the stranger's second step, with `jq` and `shasum` and no Colophon checkout: every file under the bundle against the hash the signed manifest recorded. Change one byte of a trace line and the third command still prints `Verified OK` while the fourth names the file. The signature binds the manifest; the manifest binds the files. `bundle verify` (the second command) does both, and also walks the OSCAL back-matter, the record signature, the trace chain, and the policy binding.

Then open `out/demo/agentcore-dogwood-live/bundle/report/narrative.md`: five Gateway decisions from a real ENFORCE session (allow, deny, allow, allow, deny), the Record they were checked against, the three policies the engine held (staged under `policy/`, hashed on the Record), and the proves / does-not-prove table.

Say it once: the packet proves what the Gateway decided, which policy text was in force, and that nobody changed the record since. It does not prove the policy was right, and it does not prove every call went through the Gateway. LOG_ONLY would look the same in the log and different in the Record; we refuse to blur them.
