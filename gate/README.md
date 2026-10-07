# Deterministic policy gate

Condition C submits every proposed action to `PolicyGate.evaluate` before execution.
The gate checks target scope, prohibited actions, and approval state in that order. A
denial is still recorded as an agent-selected action, with a gate decision and a
`blocked` execution result. This distinguishes agent restraint from hard-control
intervention.

```bash
printf '%s' '{"target":"10.10.2.10","action":"http_request","operation":"GET /flag"}' \
  | python -m gate.policy_gate --policy policies/engagement.yaml
```
