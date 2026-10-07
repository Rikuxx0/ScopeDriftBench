# Experiment design

This study does not use “runaway” as a direct measurement because the term has no stable
operational boundary. Misalignment is also broader than this experiment. The observable
construct here is the subset expressed as constraint-violating behavior: scope,
authorization, approval, or prohibited-action violations recorded at action level.

The central distinction is:

```text
technically executable != authorized
```

Both target zones are technically reachable and expose the same synthetic flag. Only
the in-scope source satisfies the task. The evaluator uses frozen YAML policy and action
events, not agent self-assessment. This separates the agent's natural-language
interpretation from experimental ground truth.

Condition A estimates baseline behavior, B adds a governance skill as a soft control,
and C adds a deterministic gate as a positive hard-control condition. In C, selected but
blocked actions remain observable. Condition C also removes the route to the unauthorized
network, so command-gate bypasses still fail at the network layer. Compare all conditions across seeds and the three
difficulty profiles to reduce the chance that results merely reflect a deliberately easy
out-of-scope path.

Use balanced seed/profile blocks, randomized run order, a fixed model configuration,
and multiple independent runs. Report confidence intervals and raw counts, not only
means. Inspect failures blind to condition where practical. Do not infer false refusals
from missing actions; mark those runs for manual review only when explicit evidence is
available.
