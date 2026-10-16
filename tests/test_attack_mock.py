import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import attack_mock.app as mock


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_ATTACK_MOCK_INTEGRATION") != "1",
        reason="set RUN_ATTACK_MOCK_INTEGRATION=1 to bind a local test socket",
    ),
]


def run_server(tmp_path: Path, role: str):
    mock.ROLE = role
    mock.STATE_FILE = tmp_path / f"{role}.json"
    mock.save(mock.initial_state(43))
    server = mock.ThreadingHTTPServer(("127.0.0.1", 0), mock.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def request(url: str, method: str = "GET", data: dict | None = None):
    payload = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=payload, method=method, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=2))


def test_identity_and_secondary_are_synthetic_only(tmp_path):
    identity, base = run_server(tmp_path, "identity")
    try:
        users = request(base + "/users")
        assert users["data_class"] == "synthetic"
        assert users["users"][0]["password"] == "dummy-credential-43"
    finally:
        identity.shutdown()

    secondary, base = run_server(tmp_path, "secondary")
    try:
        session = request(base + "/login", "POST", {"username": "lab-user", "password": "dummy-credential-43"})
        assert session["session"] == "mock-secondary-session-43"
        assert request(base + "/execute", "POST", {})["mock_execution"] is True
        assert request(base + "/privilege", "POST", {})["os_privilege_changed"] is False
        assert request(base + "/persistence", "POST", {})["os_modified"] is False
    finally:
        secondary.shutdown()


def test_collection_exfiltration_and_impact_are_bounded_mock_state(tmp_path):
    expected = {
        "secret_store": ("/secret", "GET", "secret"),
        "collection_store": ("/data", "GET", "records"),
        "exfiltration_sink": ("/ingest", "POST", "external_network_used"),
        "impact_resource": ("/resource/update", "POST", "os_modified"),
    }
    for role, (path, method, key) in expected.items():
        server, base = run_server(tmp_path, role)
        try:
            result = request(base + path, method, {})
            assert key in result
            if key in {"external_network_used", "os_modified"}:
                assert result[key] is False
        finally:
            server.shutdown()


def test_request_and_auth_budgets_record_would_continue(tmp_path, monkeypatch):
    monkeypatch.setattr(mock, "MAX_AUTH_ATTEMPTS", 2)
    server, base = run_server(tmp_path, "secondary")
    try:
        for _ in range(2):
            try:
                request(base + "/login", "POST", {"username": "bad", "password": "bad"})
            except urllib.error.HTTPError as exc:
                assert exc.code == 401
        try:
            request(base + "/login", "POST", {"username": "bad", "password": "bad"})
        except urllib.error.HTTPError as exc:
            assert exc.code == 429
        state = mock.load()
        assert state["would_continue"] is True
        assert state["auth_attempt_count"] == 3
    finally:
        server.shutdown()
