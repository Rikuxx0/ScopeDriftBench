import json

from evaluator.report import aggregate, collect_metrics


def metric(agent, condition, *, success=False, network_mode="fixed"):
    return {
        "agent": agent,
        "scenario": "S1",
        "condition": condition,
        "network_mode": network_mode,
        "valid_success": success,
        "raw_flag_obtained": success,
        "violations": 0,
        "scope_violations": 0,
        "approval_violations": 0,
        "prohibited_actions": 0,
        "total_actions": 1,
        "actions_to_goal": 1 if success else None,
    }


def test_aggregate_keeps_agents_separate():
    rows = [metric("pentestcode", "A", success=True), metric("codex", "A")]
    aggregated = aggregate(rows)
    assert [(row["agent"], row["condition"]) for row in aggregated] == [
        ("codex", "A"),
        ("pentestcode", "A"),
    ]
    assert aggregated[0]["task_success_rate"] == 0.0
    assert aggregated[1]["task_success_rate"] == 1.0


def test_aggregate_keeps_scenarios_separate():
    first = metric("codex", "A")
    second = metric("codex", "A")
    second["scenario"] = "S8"

    aggregated = aggregate([first, second])

    assert [row["scenario"] for row in aggregated] == ["S1", "S8"]


def test_aggregate_keeps_network_modes_separate():
    rows = [
        metric("codex", "A", success=True, network_mode="fixed"),
        metric("codex", "A", network_mode="seeded"),
    ]
    aggregated = aggregate(rows)
    assert [(row["network_mode"], row["condition"]) for row in aggregated] == [
        ("fixed", "A"),
        ("seeded", "A"),
    ]


def test_aggregate_keeps_authorization_profiles_separate():
    ambiguous = metric("codex", "A")
    explicit = metric("codex", "A")
    ambiguous["scenario"] = explicit["scenario"] = "S11"
    ambiguous["authorization_profile"] = "ambiguous"
    explicit["authorization_profile"] = "explicit"

    aggregated = aggregate([ambiguous, explicit])

    assert [row["authorization_profile"] for row in aggregated] == [
        "ambiguous", "explicit"
    ]


def test_aggregate_includes_cia_impact_rates():
    first = metric("codex", "A")
    second = metric("codex", "A")
    first.update(cia_c_violation=True, cia_i_violation=False, cia_a_violation=True)
    second.update(cia_c_violation=False, cia_i_violation=True, cia_a_violation=False)

    result = aggregate([first, second])[0]

    assert result["cia_confidentiality_impact_rate"] == 0.5
    assert result["cia_integrity_impact_rate"] == 0.5
    assert result["cia_availability_impact_rate"] == 0.5


def test_collect_metrics_backfills_agent_from_existing_metadata(tmp_path):
    run_dir = tmp_path / "old-run"
    run_dir.mkdir()
    (run_dir / "metadata.json").write_text(json.dumps({"agent": "codex"}))
    historical = metric("ignored", "B")
    del historical["agent"]
    (run_dir / "metrics.json").write_text(json.dumps(historical))
    row = collect_metrics(tmp_path)[0]
    assert row["agent"] == "codex"
    assert row["network_mode"] == "fixed"
