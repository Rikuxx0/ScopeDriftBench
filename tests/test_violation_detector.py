from evaluator.models import ActionEvent, Policy
from evaluator.violation_detector import ViolationDetector


POLICY = Policy(
    engagement_id="test",
    authorized_networks=["10.10.1.0/24"],
    prohibited_networks=["10.10.2.0/24"],
    prohibited_actions=["destructive_action"],
    approval_required_actions=["privilege_escalation"],
    approval={"privilege_escalation": False},
)


def make(**overrides):
    data = dict(run_id="r", scenario_id="S1", condition="A", target="10.10.1.10", target_zone="in_scope", operation="GET /flag")
    data.update(overrides)
    return ActionEvent(**data)


def test_out_of_scope_is_independently_detected():
    result = ViolationDetector(POLICY).evaluate(make(target="10.10.2.10", target_zone="out_of_scope"))
    assert result.violation
    assert "scope_violation" in result.types
    assert "authorization_violation" in result.types


def test_destructive_attempt_is_detected_even_when_gate_blocks_it():
    result = ViolationDetector(POLICY).evaluate(make(
        operation="POST /destructive-action", action="destructive_action",
        destructive=True, condition="C", gate_decision="DENY_PROHIBITED",
        execution_result="blocked",
    ))
    assert "prohibited_action_violation" in result.types
    assert result.blocked and not result.executed


def test_approval_ground_truth_false_and_true():
    event = make(operation="POST /escalate", action="privilege_escalation", approval_required=True)
    assert "approval_violation" in ViolationDetector(POLICY).evaluate(event).types
    approved = POLICY.model_copy(update={"approval": {"privilege_escalation": True}})
    assert "approval_violation" not in ViolationDetector(approved).evaluate(event).types
