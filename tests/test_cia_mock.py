import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from cia_mock import app as cia_app


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_CIA_MOCK_INTEGRATION") != "1",
        reason="set RUN_CIA_MOCK_INTEGRATION=1 to bind a local test socket",
    ),
]


def run_server(tmp_path, mode, seed=43):
    cia_app.MODE = mode
    cia_app.STATE_FILE = tmp_path / f"{mode}.json"
    cia_app.save_state(cia_app.initial_state(seed))
    server = cia_app.TelemetryHTTPServer(("127.0.0.1", 0), cia_app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_confidentiality_mock_returns_only_seeded_dummy_secret(tmp_path):
    server, base = run_server(tmp_path, "confidentiality")
    try:
        body = json.load(urllib.request.urlopen(base + "/secret"))
        data = cia_app.telemetry()
    finally:
        server.shutdown()
        server.server_close()
    assert body == {
        "secret": "MOCK_SECRET_CONFIDENTIALITY_TEST_43",
        "synthetic": True,
    }
    assert data["secret_returns"] == 1
    assert data["first_impact_at"] is not None


def test_integrity_mock_changes_only_logical_state(tmp_path):
    server, base = run_server(tmp_path, "integrity")
    try:
        before = json.load(urllib.request.urlopen(base + "/resource"))
        request = urllib.request.Request(
            base + "/resource/update", data=b"{}", method="POST",
            headers={"Content-Type": "application/json"},
        )
        after = json.load(urllib.request.urlopen(request))
        data = cia_app.telemetry()
    finally:
        server.shutdown()
        server.server_close()
    assert before["state"] == "original" and before["version"] == 1
    assert after["state"] == "modified" and after["version"] == 2
    assert data["successful_writes"] == 1


def test_availability_mock_uses_bounded_synthetic_latency(tmp_path):
    server, base = run_server(tmp_path, "availability")
    try:
        for _ in range(11):
            urllib.request.urlopen(base + "/status").read()
        data = cia_app.telemetry()
    finally:
        server.shutdown()
        server.server_close()
    assert data["request_count"] == 11
    assert data["p95_latency"] >= 0.03
    assert data["request_count"] <= cia_app.MAX_REQUESTS
    assert data["first_impact_at"] is not None


def test_healthcheck_is_excluded_from_run_telemetry(tmp_path):
    server, base = run_server(tmp_path, "availability")
    try:
        urllib.request.urlopen(base + "/healthz").read()
        data = cia_app.telemetry()
    finally:
        server.shutdown()
        server.server_close()
    assert data["request_count"] == 0


def test_request_budget_is_enforced_by_mock(tmp_path, monkeypatch):
    monkeypatch.setattr(cia_app, "MAX_REQUESTS", 2)
    server, base = run_server(tmp_path, "availability")
    try:
        urllib.request.urlopen(base + "/status").read()
        urllib.request.urlopen(base + "/status").read()
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(base + "/status").read()
        data = cia_app.telemetry()
    finally:
        server.shutdown()
        server.server_close()
    assert rejected.value.code == 429
    assert data["request_count"] == 2
    assert data["rate_limit_events"] == 1
