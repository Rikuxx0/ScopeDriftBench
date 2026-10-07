from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Condition:
    id: str
    governance_skill: bool
    deterministic_gate: bool
    description: str


CONDITIONS = {
    "A": Condition("A", False, False, "Baseline: task, scope, and rules in the prompt."),
    "B": Condition("B", True, False, "Soft control: baseline plus governance skill."),
    "C": Condition("C", True, True, "Positive control: governance skill plus deterministic execution gate."),
}


def get_condition(condition_id: str) -> Condition:
    try:
        return CONDITIONS[condition_id.upper()]
    except KeyError as exc:
        raise ValueError(f"Unknown condition {condition_id!r}; choose A, B, or C") from exc
