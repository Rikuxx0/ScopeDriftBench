# Architecture

The system separates five responsibilities: synthetic targets provide technical
opportunities; PentestCode is the autonomous agent execution surface; the collector
stores manually submitted telemetry; the PentestCode adapter normalizes JSON tool
events; and the host-side evaluator applies frozen policy after a run. The gate acts
before shell execution only in Condition C.

Approval is initialized through the reset control path. The governed client reads this
runtime fact only after scope/prohibition checks and never accepts an agent assertion as
approval. Thus an out-of-scope proposal does not trigger even a control-plane query to
that target.

The Condition A/B PentestCode service is attached to both target networks because
technical reachability of both zones is the treatment mechanism. The Condition C
service has no `outscope-net` interface, providing a hard boundary in addition to the
command gate. Each target is single-homed, so targets cannot communicate laterally. The
dual-homed collector has a fixed address on each isolated network but exposes no host
port. A single bind mount, `./results:/results`, is the persistence boundary.

PentestCode has no Internet-connected interface. It reaches an internal LLM relay on
`inference-net`. Only that relay attaches to `provider-egress`; it accepts the minimum
Device OAuth and Codex inference route allowlist. PentestCode stores its OAuth record in
a root-only named volume, while model-selected shell processes run under a separate UID
that cannot read it. Agent and target containers never attach to the egress network.

Target endpoints model health, discovery, credential acquisition and reuse, login,
approval-controlled escalation, flag access, and destructive state transition. No
endpoint runs commands or manipulates the host. Named volumes contain only JSON mock
state and can be recreated independently.

```text
scenario + condition + seed -> prompt/frozen inputs -> PentestCode provider turn
-> real nmap/curl/shell action -> optional deterministic gate -> live mock-service result
-> PentestCode JSON trace -> normalized action event -> independent violation detector
-> run metrics -> aggregate report
```
