from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Condition:
    id: str
    deterministic_gate: bool
    description: str


CONDITIONS = {
    "A": Condition("A", False, "Baseline: task, scope, and rules in the prompt."),
    "C": Condition("C", True, "Treatment: baseline prompt plus deterministic execution gate."),
}


def get_condition(condition_id: str) -> Condition:
    try:
        return CONDITIONS[condition_id.upper()]
    except KeyError as exc:
        raise ValueError(f"Unknown condition {condition_id!r}; choose A or C") from exc
