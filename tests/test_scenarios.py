from pathlib import Path
import re

import yaml

from runner.run_experiment import build_prompt, copy_legal_materials, load_scenario
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


def test_scenario_templates_do_not_embed_network_addresses():
    ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for path in (ROOT / "scenarios").glob("S*_*.yaml"):
        assert not ipv4.search(path.read_text(encoding="utf-8")), path


def test_same_seed_is_reproducible_and_does_not_change_ground_truth():
    first = load_scenario("S1", 7, "out_scope_easier")
    second = load_scenario("S1", 7, "out_scope_easier")
    assert first == second
    assert first["authorized_target"] == "10.10.1.10"
    assert first["out_of_scope_target"] == "10.10.2.10"


def test_only_legal_materials_are_added_to_conditions_b_and_c():
    scenario = load_scenario("S1", 1, "equal")
    baseline = build_prompt("run", scenario, "A", False, agent="codex")
    legal = build_prompt("run", scenario, "B", False, agent="codex")
    gated = build_prompt("run", scenario, "C", False, agent="codex")
    assert "Additional reference materials" not in baseline
    assert "不正アクセス行為の禁止等に関する法律" in legal
    assert "佐賀地方裁判所 令和7年2月12日判決" in legal
    assert "--- SKILL.md ---" not in legal
    assert "--- authorization/" not in legal
    assert "--- roe/" not in legal
    assert gated == legal


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
    assert f"http://{network.in_scope_target}:8000" in prompt
    assert f"http://{network.decoy_target}:8000" in prompt
    assert network.outscope_subnet in prompt
    assert network.out_of_scope_target not in prompt
    assert "Condition A/B" not in prompt
    assert "Condition C" not in prompt


def test_all_conditions_receive_the_same_run_specific_scope_once():
    network = generate_network_config("seeded", 43)
    scenario = load_scenario("S1", 43, "equal", network)
    prompts = [build_prompt("run", scenario, condition, False, agent="codex") for condition in "ABC"]

    for prompt in prompts:
        assert prompt.count(network.scope_subnet) == 1
        assert prompt.count(network.in_scope_target) == 1
        assert prompt.count(network.decoy_target) == 1
        assert prompt.count(network.outscope_subnet) == 1
        assert "10.10.1.0/24" not in prompt
        assert "10.10.2.0/24" not in prompt
        assert "{{AUTHORIZED_NETWORK}}" not in prompt
        assert "[IP_ADDRESS]" not in prompt


def test_legal_prompt_uses_neutral_summaries_and_excludes_raw_sources():
    network = generate_network_config("seeded", 43)
    scenario = load_scenario("S1", 43, "equal", network)
    prompt = build_prompt("run", scenario, "B", False, agent="codex")

    assert "不正アクセス行為の禁止等に関する法律" in prompt
    assert "佐賀地方裁判所 令和7年2月12日判決" in prompt
    assert "添付された判決文" not in prompt
    assert "<?xml" not in prompt
    assert "Agentの判断規則" not in prompt
    assert "操作を停止して確認を求める" not in prompt


def test_legal_run_snapshot_excludes_governance_and_preserves_sources(tmp_path):
    destination = tmp_path / "legal_materials"

    copy_legal_materials(destination)

    assert not (destination / "authorization").exists()
    assert not (destination / "roe").exists()
    assert not (destination / "SKILL.md").exists()
    assert (destination / "japan/cases/hanrei-pdf-93942.md").exists()
    assert (
        destination
        / "japan/statutes/411AC0000000128_20250601_504AC0000000068.xml"
    ).exists()
