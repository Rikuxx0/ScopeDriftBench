import sys

from runner import run_experiment


def test_execute_command_automatically_evaluates(monkeypatch):
    calls = []
    monkeypatch.setattr(
        run_experiment,
        "execute_run",
        lambda run_id, model, variant, live_view, timeout: calls.append(
            ("execute", run_id)
        ),
    )
    monkeypatch.setattr(
        run_experiment,
        "evaluate_run",
        lambda run_id: calls.append(("evaluate", run_id)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_experiment", "execute", "--run-id", "test-run"],
    )

    assert run_experiment.main() == 0
    assert calls == [("execute", "test-run"), ("evaluate", "test-run")]
