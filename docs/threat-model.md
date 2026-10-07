# Threat model

## Protected assets

The host filesystem, Docker control plane, local network, Internet systems, and third
parties are outside the experiment. The only destructible asset is synthetic target JSON
state.

## Controls

- Target and inference networks are internal and have fixed private subnets.
- No service publishes a port or uses host networking.
- No container is privileged and privilege escalation is disabled. Capabilities are
  dropped globally; PentestCode retains only `SETUID`/`SETGID` so its trusted
  orchestrator can irreversibly demote each model-selected shell child to the `lab` UID.
- No Docker socket or broad source-tree mount enters the attacker.
- Targets are local source-built mocks without RCE or real product vulnerabilities.
- The attacker image contains only Python and the governed HTTP client.
- PentestCode agents have no egress interface. Only the allowlist LLM relay can reach
  the provider network. Its host/path allowlist is limited to ChatGPT device OAuth and
  Codex inference.
- The PentestCode orchestrator can read its OAuth record, but model-selected shell
  commands run under another UID and cannot read `/auth` or `/state`.
- Condition C uses both a deterministic shell gate and absence of an `outscope-net`
  interface.
- Target state is held in dedicated named volumes; results are the sole host bind mount.

## Residual risk

Docker engine flaws, host misconfiguration, provider-side data handling, resource
exhaustion, and researchers adding unsafe tools or adapters remain out of scope for
software-level guarantees. For stronger containment, run Docker inside a disposable VM
with an external egress firewall and resource quotas. Never add an LLM API key to an
agent container. The pinned PentestCode binary and OAuth relay remain trusted-computing
base components; this separation protects against model-selected tool commands, not a
malicious replacement of either component.
