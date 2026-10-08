from pathlib import Path

import yaml

from runner.run_experiment import build_prompt, load_scenario
from runner.network_config import generate_network_config


ROOT = Path(__file__).parents[1]


def test_all_scenarios_exist_and_support_difficulty_profiles():
    for number in range(1, 6):
        files = list((ROOT / "scenarios").glob(f"S{number}_*.yaml"))
        assert len(files) == 1
        scenario = yaml.safe_load(files[0].read_text())
        assert set(scenario["allowed_difficulty_profiles"]) == {
            "equal", "in_scope_easier", "out_scope_easier"
        }


def test_same_seed_is_reproducible_and_does_not_change_ground_truth():
    first = load_scenario("S1", 7, "out_scope_easier")
    second = load_scenario("S1", 7, "out_scope_easier")
    assert first == second
    assert first["authorized_target"] == "10.10.1.10"
    assert first["out_of_scope_target"] == "10.10.2.10"


def test_governance_bundle_only_appears_in_conditions_b_and_c():
    scenario = load_scenario("S1", 1, "equal")
    baseline = build_prompt("run", scenario, "A", False)
    governed = build_prompt("run", scenario, "B", False)
    gated = build_prompt("run", scenario, "C", False)
    assert "Governance skill bundle" not in baseline
    assert "Authorization\n" in governed
    assert "Prohibited actions\n" in governed
    assert "deterministic gate" in gated


def test_pentestcode_prompt_does_not_prescribe_tools_or_commands():
    scenario = load_scenario("S1", 1, "equal")
    prompt = build_prompt("run", scenario, "A", False, agent="pentestcode")
    assert "Execution requirements" not in prompt
    assert "nmap" not in prompt
    assert "curl" not in prompt
    assert "lab-request" not in prompt


def test_seeded_network_is_frozen_into_scenario_and_prompt():
    network = generate_network_config("seeded", 42)
    scenario = load_scenario("S1", 42, "equal", network)
    prompt = build_prompt("run", scenario, "A", False, agent="codex")
    assert scenario["authorized_target"] == network.in_scope_target
    assert scenario["out_of_scope_target"] == network.out_of_scope_target
    assert network.scope_subnet in prompt
    assert network.in_scope_target in prompt
    assert network.outscope_subnet in prompt
