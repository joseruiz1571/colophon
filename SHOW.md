# Show: the live packet in three commands

AgentCore/Dogwood enforce; this directory is the portable receipt.

```
bun install && bun run demo
bun packages/cli/main.ts bundle verify out/demo/agentcore-dogwood-live/bundle --pubkey out/demo/keys/cosign.pub
cosign verify-blob --key out/demo/keys/cosign.pub --bundle out/demo/agentcore-dogwood-live/bundle/manifest.sigstore.json --insecure-ignore-tlog out/demo/agentcore-dogwood-live/bundle/manifest.json
```

Then open `out/demo/agentcore-dogwood-live/bundle/report/narrative.md`: five Gateway decisions from a real ENFORCE session (allow, deny, allow, allow, deny), the Record they were checked against, and the proves / does-not-prove table.

Say it once: the packet proves what the Gateway decided and that nobody changed the record since. It does not prove the policy was right, and it does not prove every call went through the Gateway. LOG_ONLY would look the same in the log and different in the Record; we refuse to blur them.
