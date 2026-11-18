"""Public benchmark CLI keeps the legacy schema without exposing conditions."""
import json
from pathlib import Path
import subprocess

import pytest
import yaml

import pentestlab_cli
from runner.benchmark_results import BENCHMARK_FORMAT
from runner.run_experiment import available_scenario_ids


def test_scenarios_lists_existing_task_names_and_descriptions(capsys):
    assert pentestlab_cli.main(["scenarios"]) == 0
    rows = capsys.readouterr().out.strip().splitlines()
    assert len(rows) == len(available_scenario_ids()) == 14
    assert rows[0].startswith("S1\tScope Boundary\t")
    assert rows[-1].startswith("S14\tEnterprise Attack Path\t")


def test_run_without_condition_uses_open_standard_environment(monkeypatch):
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    monkeypatch.setattr(pentestlab_cli, "read_config", lambda: config)
    recorded = []
    monkeypatch.setattr(pentestlab_cli, "prepare_run", lambda args: recorded.append(args) or Path("/tmp/benchmark-test"))
    assert pentestlab_cli.main(["run", "--scenario", "S1", "--prepare-only"]) == 0
    assert recorded[0].condition == "A"
    assert recorded[0].scenario == "S1"


def test_old_config_condition_is_ignored_without_rewriting(tmp_path):
    path = tmp_path / "config.yaml"
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    config["experiment"]["condition"] = "C"
    path.write_text(yaml.safe_dump(config))
    loaded = pentestlab_cli.read_config(path)
    assert "condition" not in loaded["experiment"]
    assert yaml.safe_load(path.read_text())["experiment"]["condition"] == "C"


def test_public_run_and_compare_do_not_accept_condition():
    for command in ("run", "compare"):
        with pytest.raises(SystemExit) as error:
            pentestlab_cli.parser().parse_args([command, "--condition", "C"])
        assert error.value.code == 2


def test_results_list_and_direct_lookup_exclude_old_condition_runs(monkeypatch, tmp_path, capsys):
    for name, marker in (("old", None), ("new", BENCHMARK_FORMAT)):
        directory = tmp_path / "results" / name
        directory.mkdir(parents=True)
        metadata = {"run_id": name, "scenario": "S1", "condition": "A", "status": "evaluated"}
        if marker:
            metadata["benchmark_format"] = marker
        (directory / "metadata.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(pentestlab_cli, "ROOT", tmp_path)
    assert pentestlab_cli.main(["results"]) == 0
    output = capsys.readouterr().out
    assert "new  S1" in output
    assert "old  S1" not in output
    assert pentestlab_cli.main(["results", "--run-id", "old"]) == 1
    assert pentestlab_cli.main(["results", "--run-id", "new"]) == 0


def test_new_cli_and_old_wrapper_share_commands():
    root = Path(pentestlab_cli.__file__).parent
    for command in ("--help", "scenarios", "providers"):
        new = subprocess.run([str(root / "scopedriftbench"), command], capture_output=True, text=True, check=True)
        old = subprocess.run([str(root / "pentestlab"), command], capture_output=True, text=True, check=True)
        assert new.stdout == old.stdout
        if command == "--help":
            assert "scopedriftbench" in new.stdout


def test_existing_config_is_read_until_new_config_is_written(monkeypatch, tmp_path):
    new_path = tmp_path / ".scopedriftbench.yaml"
    old_path = tmp_path / ".pentestlab.yaml"
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    config["model"] = "legacy-model"
    old_path.write_text(yaml.safe_dump(config))
    monkeypatch.setattr(pentestlab_cli, "CONFIG_PATH", new_path)
    monkeypatch.setattr(pentestlab_cli, "LEGACY_CONFIG_PATH", old_path)
    assert pentestlab_cli.read_config()["model"] == "legacy-model"
    config["model"] = "new-model"
    pentestlab_cli.write_config(config)
    assert pentestlab_cli.read_config()["model"] == "new-model"
    assert yaml.safe_load(old_path.read_text())["model"] == "legacy-model"
