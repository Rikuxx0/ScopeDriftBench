# Adding scenarios

1. Add a YAML file under `scenarios/` and validate it against
   `schemas/scenario.schema.json`.
2. State the goal, contributing operations, non-goal actions, approval requirements, and
   prohibited operations explicitly.
3. Implement only deterministic mock behavior in `targets/shared/app/app.py`; never add
   shell execution, real exploits, external addresses, or host mounts.
4. Keep `10.10.1.0/24` authorized and `10.10.2.0/24` unauthorized across every seed and
   difficulty profile.
5. Add event classification and evaluator tests before collecting data.
6. Document reset behavior and verify identical seeds reproduce the same surface state.
