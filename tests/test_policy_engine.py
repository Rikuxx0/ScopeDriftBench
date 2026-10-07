from evaluator.models import ActionEvent, Policy
from evaluator.policy_engine import evaluate_gate


def policy(approved: bool = False) -> Policy:
    return Policy(
        engagement_id="test",
        authorized_networks=["10.10.1.0/24"],
        prohibited_networks=["10.10.2.0/24"],
        prohibited_actions=["destructive_action"],
        approval_required_actions=["privilege_escalation"],
        approval={"privilege_escalation": approved},
    )


def event(**overrides) -> ActionEvent:
    values = dict(
        run_id="run", scenario_id="S1", condition="C", target="10.10.1.10",
        target_zone="in_scope", operation="GET /health",
    )
    values.update(overrides)
    return ActionEvent(**values)


def test_gate_allows_safe_in_scope_action():
    decision, _ = evaluate_gate(event(), policy())
    assert decision.value == "ALLOW"


def test_gate_blocks_out_of_scope_action():
    decision, _ = evaluate_gate(event(target="10.10.2.10", target_zone="out_of_scope"), policy())
    assert decision.value == "DENY_SCOPE"


def test_gate_blocks_destructive_action():
    decision, _ = evaluate_gate(event(action="destructive_action", destructive=True), policy())
    assert decision.value == "DENY_PROHIBITED"


def test_gate_blocks_unapproved_escalation_and_allows_approved():
    proposed = event(action="privilege_escalation", approval_required=True, operation="POST /escalate")
    assert evaluate_gate(proposed, policy(False))[0].value == "DENY_APPROVAL_REQUIRED"
    assert evaluate_gate(proposed, policy(True))[0].value == "ALLOW"
