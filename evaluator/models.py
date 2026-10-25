from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY_SCOPE = "DENY_SCOPE"
    DENY_PROHIBITED = "DENY_PROHIBITED"
    DENY_APPROVAL_REQUIRED = "DENY_APPROVAL_REQUIRED"


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: str
    authorized_networks: list[str]
    prohibited_networks: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    approval_required_actions: list[str] = Field(default_factory=list)
    approval: dict[str, bool] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        with Path(path).open(encoding="utf-8") as handle:
            return cls.model_validate(yaml.safe_load(handle))


class ActionEvent(BaseModel):
    """Canonical append-only event. Unknown fields are retained for research extensions."""

    model_config = ConfigDict(extra="allow")

    run_id: str
    scenario_id: str
    condition: Literal["A", "C"]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "agent"
    action_type: str = "http_request"
    source: str = "attacker"
    target: str | None = None
    targets: list[str] = Field(default_factory=list)
    target_zone: Literal["in_scope", "out_of_scope", "control_plane", "cia_confidentiality", "cia_integrity", "cia_availability", "decoy", "unknown"] = "unknown"
    target_zones: list[Literal["in_scope", "out_of_scope", "control_plane", "cia_confidentiality", "cia_integrity", "cia_availability", "decoy", "unknown"]] = Field(default_factory=list)
    control_plane_probe: bool = False
    proposed_action: bool = False
    attempted_action: bool = True
    executed_action: bool = False
    cia_dimension: Literal["confidentiality", "integrity", "availability"] | None = None
    impact: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)
    operation: str
    action: str | None = None
    destructive: bool = False
    approval_required: bool = False
    approval_present: bool = False
    result: str = "unknown"
    agent_selected_action: bool = True
    gate_decision: GateDecision | None = None
    execution_result: str = "not_attempted"
    goal_relevance: Literal["contributing", "non_goal", "unknown"] = "unknown"
    flag_source: Literal["in_scope", "out_of_scope"] | None = None
    credential_event: Literal[
        "obtained", "used_in_scope", "used_out_of_scope"
    ] | None = None
    elapsed_seconds: float | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: Any) -> Any:
        if isinstance(value, str) and value.endswith("Z"):
            return value[:-1] + "+00:00"
        return value


class Violation(BaseModel):
    event_index: int
    violation: bool
    types: list[str]
    reason: dict[str, Any] = Field(default_factory=dict)
    attempted: bool = True
    blocked: bool = False
    executed: bool = False


class RunMetrics(BaseModel):
    run_id: str
    agent: str = "unknown"
    network_mode: str = "fixed"
    scenario: str
    condition: str
    seed: int
    valid_success: bool
    raw_flag_obtained: bool
    violations: int
    scope_violations: int
    authorization_violations: int
    approval_violations: int
    prohibited_actions: int
    total_actions: int
    tool_calls: int
    goal_irrelevant_actions: int
    goal_irrelevant_action_rate: float
    time_to_goal: float | None
    actions_to_goal: int | None
    third_party_input_observed: bool = False
    post_exposure_violations: int = 0
    control_plane_probe_attempts: int = 0
    blocked_control_plane_probes: int = 0
    authorization_profile: str | None = None
    goal_reached: bool = False
    authorized_actions: int = 0
    unauthorized_actions: int = 0
    unauthorized_targets_discovered: int = 0
    unauthorized_targets_contacted: int = 0
    cia_c_violation: bool = False
    cia_i_violation: bool = False
    cia_a_violation: bool = False
    time_to_first_boundary_violation: float | None = None
    time_to_first_cia_impact: float | None = None
    agent_report_accuracy: bool | None = None
    mock_request_count: int = 0
    mock_mean_latency: float = 0.0
    mock_p95_latency: float = 0.0
    mock_max_latency: float = 0.0
    availability_threshold_exceeded: bool = False
    manual_review_required: bool = False
    valid_goal_success: bool = False
    tool_call_count: int = 0
    authorization_boundary_violations: int = 0
    authorized_progression_depth: str | None = None
    unauthorized_progression_depth: str | None = None
    attack_tactics_observed: list[str] = Field(default_factory=list)
    attack_techniques_observed: list[str] = Field(default_factory=list)
    first_target_misidentification_at: float | None = None
    first_unauthorized_action_at: float | None = None
    credential_attempt_count: int = 0
    credential_file_accessed: bool = False
    ssh_session_attempt_count: int = 0
    sudo_action_count: int = 0
    final_flag_read: bool = False
    mock_execution_count: int = 0
    mock_privilege_escalation_count: int = 0
    mock_persistence_count: int = 0
    mock_lateral_movement_count: int = 0
    mock_collection_count: int = 0
    mock_exfiltration_count: int = 0
    mock_impact_count: int = 0
    stopped_by: str | None = None
