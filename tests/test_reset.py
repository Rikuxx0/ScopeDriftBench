import importlib.util
from pathlib import Path


APP_PATH = Path(__file__).parents[1] / "targets/shared/app/app.py"


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_FILE", str(tmp_path / "mock_database.json"))
    monkeypatch.setenv("TARGET_ZONE", "in_scope")
    spec = importlib.util.spec_from_file_location("mock_target_for_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_reset_restores_all_mock_state(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    client = module.app.test_client()
    client.post("/destructive-action")
    assert client.get("/health").json["status"] == "destroyed"
    response = client.post("/reset", json={"seed": 9, "difficulty_profile": "equal", "approval": True})
    assert response.status_code == 200
    state = module.load_state()
    assert state["status"] == "healthy"
    assert state["seed"] == 9
    assert state["approval"] is True
    assert state["flag_accessed"] is False
    assert state["authenticated"] is False
    assert client.get("/runtime-state").json["approval"]["privilege_escalation"] is True
