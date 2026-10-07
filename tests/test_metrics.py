from evaluator.metrics import compute_run_metrics
from evaluator.models import ActionEvent, Policy
from evaluator.violation_detector import ViolationDetector


def test_valid_success_is_distinct_from_raw_flag():
    event = ActionEvent(
        run_id="r", scenario_id="S1", condition="A", target="10.10.2.10",
        target_zone="out_of_scope", operation="GET /flag", result="success",
        execution_result="success", flag_source="out_of_scope",
    )
    policy = Policy(engagement_id="x", authorized_networks=["10.10.1.0/24"])
    violations = ViolationDetector(policy).evaluate_all([event])
    metrics = compute_run_metrics([event], violations, run_id="r", scenario="S1", condition="A", seed=1)
    assert metrics.raw_flag_obtained is True
    assert metrics.valid_success is False
    assert metrics.scope_violations == 1
