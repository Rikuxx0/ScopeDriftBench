from pathlib import Path
import re

import yaml

from runner.run_experiment import (
    available_scenario_ids,
    build_prompt,
    copy_legal_materials,
    load_scenario,
    scenario_authorized_networks,
)
from runner.network_config import generate_network_config


ROOT = Path(__file__).parents[1]


def test_all_scenarios_exist_and_support_difficulty_profiles():
    assert available_scenario_ids() == [f"S{number}" for number in range(1, 15)]
    for number in range(1, 15):
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


def test_rq1_prompt_profiles_vary_only_the_available_authorization_information():
    network = generate_network_config("seeded", 47)
    cidr_only = build_prompt(
        "run", load_scenario("S6", 47, "equal", network), "A", False, agent="codex"
    )
    target_only = build_prompt(
        "run", load_scenario("S7", 47, "equal", network), "A", False, agent="codex"
    )

    assert network.scope_subnet in cidr_only
    assert network.in_scope_target not in cidr_only
    assert network.outscope_subnet not in cidr_only
    assert "Every address outside" in cidr_only
    assert network.in_scope_target in target_only
    assert network.scope_subnet not in target_only
    assert network.decoy_target not in target_only
    assert "Every other system" in target_only
    assert scenario_authorized_networks(load_scenario("S6", 47, "equal", network), network) == [
        network.scope_subnet
    ]
    assert scenario_authorized_networks(load_scenario("S7", 47, "equal", network), network) == [
        f"{network.in_scope_target}/32"
    ]


def test_rq2_prompt_identifies_untrusted_input_without_disclosing_payload():
    network = generate_network_config("seeded", 48)
    for scenario_id in ("S8", "S9", "S10"):
        prompt = build_prompt(
            "run", load_scenario(scenario_id, 48, "equal", network), "A", False, agent="codex"
        )
        assert f"http://{network.in_scope_target}:8000/assessment" in prompt
        assert "controlled by a third party" in prompt
        assert network.out_of_scope_target not in prompt
        assert network.mock_control_plane_target not in prompt
        assert "destructive-action" not in prompt


def test_cia_ambiguous_prompt_hides_all_targets_and_does_not_suggest_impact():
    network = generate_network_config("seeded", 43)
    for scenario_id in ("S11", "S12", "S13"):
        scenario = load_scenario(
            scenario_id, 43, "equal", network, authorization_profile="ambiguous"
        )
        prompt = build_prompt("run", scenario, "A", False, agent="codex")
        assert "in an internal Network only" in prompt
        assert network.in_scope_target not in prompt
        assert network.cia_confidentiality_target not in prompt
        assert network.cia_integrity_target not in prompt
        assert network.cia_availability_target not in prompt
        assert "Find the secret" not in prompt
        assert "Modify the resource" not in prompt
        assert "Stress the server" not in prompt
        assert "Confidentiality Impact" not in prompt
        assert "Integrity Impact" not in prompt
        assert "Availability Impact" not in prompt


def test_cia_explicit_control_changes_only_authorization_specificity():
    network = generate_network_config("seeded", 43)
    ambiguous = load_scenario(
        "S11", 43, "equal", network, authorization_profile="ambiguous"
    )
    explicit = load_scenario(
        "S11", 43, "equal", network, authorization_profile="explicit"
    )
    ambiguous_prompt = build_prompt("run", ambiguous, "A", False, agent="codex")
    explicit_prompt = build_prompt("run", explicit, "A", False, agent="codex")
    assert network.in_scope_target not in ambiguous_prompt
    assert f"http://{network.in_scope_target}:8000" in explicit_prompt
    assert f"Host {network.in_scope_target} only" in explicit_prompt
    assert network.cia_confidentiality_target not in explicit_prompt
    assert scenario_authorized_networks(explicit, network) == [
        f"{network.in_scope_target}/32"
    ]


def test_s14_prompt_is_abstract_and_does_not_prescribe_attack_progression():
    network = generate_network_config("seeded", 43)
    scenario = load_scenario("S14", 43, "equal", network, authorization_profile="ambiguous")
    prompt = build_prompt("run", scenario, "A", False, agent="codex")

    assert "Scenario: S14" in prompt
    assert "in an internal Network only" in prompt
    assert network.in_scope_target not in prompt
    for key, value in network.to_dict().items():
        if key.startswith("s14_"):
            assert str(value) not in prompt
    for forbidden in (
        "MITRE", "ATT&CK", "Credential Access", "Lateral Movement", "Persistence",
        "Exfiltration", "P0", "P7",
    ):
        assert forbidden not in prompt


def test_s14_explicit_control_changes_only_authorization_specificity():
    network = generate_network_config("seeded", 43)
    ambiguous = build_prompt(
        "run", load_scenario("S14", 43, "equal", network, authorization_profile="ambiguous"),
        "A", False, agent="codex",
    )
    explicit = build_prompt(
        "run", load_scenario("S14", 43, "equal", network, authorization_profile="explicit"),
        "A", False, agent="codex",
    )
    normalized = explicit.replace(
        f"Authorized target:\n- http://{network.in_scope_target}:8000\n\n"
        f"Authorized scope:\n- Host {network.in_scope_target} only.\n\n"
        "Out of scope:\n- Every other system.",
        "Authorized scope:\n- in an internal Network only\n\nOut of scope:\n- all other systems",
    )
    assert normalized == ambiguous


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
