import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import socket
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import pytest

import pentestlab_cli
from runner.adapters import Experiment, LocalModelAdapter, parse_local_events
from runner.providers import LocalProvider, ModelInfo, ProviderError
from runner import run_experiment


@pytest.fixture
def provider_server(monkeypatch):
    routes = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self):
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                self.server.last_body = json.loads(self.rfile.read(length))
            status, body = routes.get((self.command, self.path), (404, {"error": "missing"}))
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "http://example.com/v1/models")
            self.send_header("Content-Type", "application/json")
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = respond
        do_POST = respond

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        # The local Codex sandbox forbids even loopback binds.  Exercise the
        # identical request/response handling through a mock HTTP transport.
        class FakeServer:
            last_body = None

        fake = FakeServer()

        class FakeOpener:
            def open(self, request, timeout):
                if urlsplit(request.full_url).port == 1:
                    raise URLError("not running")
                if request.data is not None:
                    fake.last_body = json.loads(request.data)
                path = urlsplit(request.full_url).path
                key = (request.get_method(), path)
                if key not in routes:
                    raise URLError("not running")
                status, body = routes[key]
                if status == 302:
                    raise ProviderError("Provider redirected a request; redirects are disabled")
                if status >= 400:
                    raise HTTPError(request.full_url, status, "error", {}, BytesIO(b"{}"))
                return BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())

        monkeypatch.setattr("runner.providers.build_opener", lambda *args: FakeOpener())
        yield "http://127.0.0.1:12345/v1", routes, fake
    else:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{server.server_port}/v1", routes, server
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_ollama_model_discovery_and_tool_completion(provider_server):
    url, routes, server = provider_server
    routes[("GET", "/api/tags")] = (200, {"models": [{
        "name": "local:7b", "digest": "abc", "details": {"quantization_level": "Q4_K_M"},
    }]})
    routes[("POST", "/v1/chat/completions")] = (200, {"choices": [{"message": {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "shell", "arguments": '{"command":"pwd"}',
        }}],
    }, "finish_reason": "tool_calls"}]})
    client = LocalProvider("ollama", url)
    info = client.select_model("local:7b")
    assert info.quantization == "Q4_K_M"
    assert info.tool_calling is None
    answer = client.infer("local:7b", [{"role": "user", "content": "hello"}],
                          [LocalModelAdapter.TOOL], temperature=0)
    assert answer["message"]["tool_calls"][0]["id"] == "c1"
    assert server.last_body["temperature"] == 0
    assert server.last_body["tools"][0]["function"]["name"] == "shell"


def test_lmstudio_capability_and_missing_model(provider_server):
    url, routes, _ = provider_server
    routes[("GET", "/api/v1/models")] = (200, {"models": [
        {"key": "tool-model", "max_context_length": 32768,
         "capabilities": {"trained_for_tool_use": True},
         "quantization": {"name": "Q4_K_M"},
         "loaded_instances": [{"config": {"context_length": 4096}}]},
        {"key": "text-model", "capabilities": {"tool_use": False}},
    ]})
    client = LocalProvider("lmstudio", url)
    assert client.select_model("tool-model").loaded is True
    assert client.model_info("tool-model").context_window == 4096
    assert client.model_info("tool-model").quantization == "Q4_K_M"
    with pytest.raises(ProviderError, match="no tool calling"):
        client.select_model("text-model")
    with pytest.raises(ProviderError, match="not listed"):
        client.select_model("not-loaded")


@pytest.mark.parametrize("kind,path,body", [
    ("ollama", "/api/tags", {"models": "invalid"}),
    ("lmstudio", "/api/v1/models", {"models": [{"wrong": "shape"}]}),
    ("lmstudio", "/api/v1/models", b"not-json"),
])
def test_invalid_provider_responses(provider_server, kind, path, body):
    url, routes, _ = provider_server
    routes[("GET", path)] = (200, body)
    with pytest.raises(ProviderError):
        LocalProvider(kind, url).list_models()


def test_disconnected_and_redirected_provider(provider_server):
    url, routes, _ = provider_server
    routes[("GET", "/api/tags")] = (302, {})
    with pytest.raises(ProviderError, match="redirect|HTTP 302"):
        LocalProvider("ollama", url).list_models()
    with pytest.raises(ProviderError, match="Cannot connect"):
        LocalProvider("ollama", "http://127.0.0.1:1/v1", retries=0, timeout=.1).list_models()


def test_provider_timeout_and_path_pin(monkeypatch):
    client = LocalProvider("ollama", "http://127.0.0.1:11434/v1", retries=0)
    monkeypatch.setattr(client._opener, "open", lambda *args, **kwargs: (_ for _ in ()).throw(socket.timeout()))
    with pytest.raises(ProviderError, match="Cannot connect"):
        client.list_models()
    with pytest.raises(ProviderError, match="allowlisted"):
        client._request("GET", "/unapproved")
    with pytest.raises(ValueError):
        LocalProvider("ollama", "http://user:password@127.0.0.1/v1")


def test_streaming_sse_chunks(provider_server):
    url, routes, _ = provider_server
    routes[("POST", "/v1/chat/completions")] = (
        200, b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
             b'data: [DONE]\n\n',
    )
    chunks = list(LocalProvider("lmstudio", url).stream("model", [], []))
    assert chunks[0]["choices"][0]["delta"]["content"] == "hello"


def test_ollama_show_reports_capability_and_context(provider_server):
    url, routes, _ = provider_server
    routes[("GET", "/api/tags")] = (200, {"models": [{"name": "good", "details": {}}]})
    routes[("GET", "/api/ps")] = (200, {"models": [{"name": "good", "context_length": 8192}]})
    routes[("POST", "/api/show")] = (200, {"capabilities": ["completion", "tools"]})
    model = LocalProvider("ollama", url).select_model("good")
    assert model.loaded is True and model.tool_calling is True
    assert model.context_window == 8192


class FakeProvider:
    kind = "ollama"
    origin = "http://127.0.0.1:11434"
    timeout = 10

    def __init__(self, malformed=False):
        self.calls = 0
        self.malformed = malformed

    def select_model(self, model):
        return ModelInfo(model)

    def infer(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return {"message": {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call-1", "type": "function", "function": {
                    "name": "shell", "arguments": '{"command":"curl http://10.10.1.10:8000/health"}'
                    if not self.malformed else '{"command":123}',
                },
            }]}}
        return {"message": {"role": "assistant", "content": "Finished", "tool_calls": []}}


def experiment(tmp_path):
    (tmp_path / "events.jsonl").touch()
    return Experiment("run", tmp_path, {"run_id": "run", "scenario": "S1", "condition": "C",
                                        "network": {"scope_subnet": "10.10.1.0/24",
                                                    "outscope_subnet": "10.10.2.0/24"}})


def test_local_agent_emits_evaluable_trace(monkeypatch, tmp_path):
    adapter = LocalModelAdapter(provider=FakeProvider(), model="test", live_view="json")
    adapter.prepare(experiment(tmp_path))
    monkeypatch.setattr(adapter, "_execute_tool", lambda command: (0, "HTTP/1.1 200 OK"))
    assert adapter.run("Test prompt") == "Finished"
    trace = (tmp_path / "local_trace.jsonl").read_text()
    assert '"type": "tool_requested"' in trace
    assert '"type": "gate_decision"' in trace
    events = parse_local_events(trace, adapter.experiment.metadata)
    assert len(events) == 1 and events[0].source == "local"
    assert events[0].target_zone == "in_scope"
    assert adapter.experiment.metadata["harness_system_prompt_sha256"]
    assert adapter.experiment.metadata["harness_tools"][0]["function"]["name"] == "shell"
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 1


def test_bad_tool_call_does_not_execute(monkeypatch, tmp_path):
    adapter = LocalModelAdapter(provider=FakeProvider(malformed=True), model="test", live_view="json")
    adapter.prepare(experiment(tmp_path))
    monkeypatch.setattr(adapter, "_execute_tool", lambda command: pytest.fail("must not execute"))
    with pytest.raises(ProviderError, match="Invalid shell command"):
        adapter.run("Test prompt")
    assert (tmp_path / "events.jsonl").read_text() == ""


def test_local_tools_use_existing_condition_c_container(monkeypatch, tmp_path):
    adapter = LocalModelAdapter(provider=FakeProvider(), model="test")
    adapter.prepare(experiment(tmp_path))
    seen = []

    def fake_run(command, **kwargs):
        seen.append(command)
        return argparse.Namespace(returncode=126, stdout="", stderr="POLICY_GATE:DENY_SCOPE")

    monkeypatch.setattr("runner.adapters.subprocess.run", fake_run)
    code, output = adapter._execute_tool("curl http://10.10.2.10:8000/flag")
    assert code == 126 and "POLICY_GATE:DENY_SCOPE" in output
    assert "codex-gated" in seen[0]
    assert "--user" not in seen[0]
    assert "/bin/sh" in seen[0]
    assert all("11434" not in str(value) for value in seen[0])


def test_cli_interactive_selection(monkeypatch):
    answers = iter(["3", "1", "1", "S13", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(pentestlab_cli, "model_rows", lambda config, provider: [{"model_id": "local:7b"}])
    selected = pentestlab_cli.wizard(pentestlab_cli.read_config(Path("/nonexistent")))
    assert selected["harness"] == "local"
    assert selected["provider"] == "ollama"
    assert selected["model"] == "local:7b"
    assert selected["experiment"]["scenario"] == "S13"
    assert "condition" not in selected["experiment"]


def test_cli_noninteractive_prepare_and_config(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    pentestlab_cli.write_config(config, config_path)
    assert pentestlab_cli.read_config(config_path)["experiment"]["scenario"] == "S1"
    monkeypatch.setattr(pentestlab_cli, "read_config", lambda: config)
    recorded = []
    monkeypatch.setattr(pentestlab_cli, "prepare_run", lambda args: recorded.append(args) or Path("/tmp/example-run"))
    assert pentestlab_cli.main(["run", "--non-interactive", "--scenario", "S12",
                                "--prepare-only"]) == 0
    assert recorded[0].scenario == "S12" and recorded[0].condition == "A"
    with pytest.raises(SystemExit) as removed:
        pentestlab_cli.main(["run", "--condition", "C"])
    assert removed.value.code == 2
    with pytest.raises(SystemExit) as error:
        pentestlab_cli.main(["run", "--network-mode", "invalid"])
    assert error.value.code == 2


def test_cli_execute_restores_prepared_local_settings(monkeypatch, tmp_path):
    run_dir = tmp_path / "results/prepared"
    run_dir.mkdir(parents=True)
    (run_dir / "metadata.json").write_text(json.dumps({
        "run_id": "prepared", "agent": "local", "provider": "lmstudio",
        "benchmark_format": "authorization-boundary-v1",
        "model_id": "local:8b", "provider_endpoint": "http://127.0.0.1:1234/v1",
        "generation_parameters": {"temperature": 0, "max_output_tokens": 1024,
                                  "request_timeout_seconds": 30},
    }))
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    monkeypatch.setattr(pentestlab_cli, "ROOT", tmp_path)
    monkeypatch.setattr(pentestlab_cli, "read_config", lambda: config)
    calls = []
    monkeypatch.setattr(pentestlab_cli, "do_execute", lambda run_id, settings, **kwargs: calls.append((run_id, settings, kwargs)))
    assert pentestlab_cli.main(["execute", "--run-id", "prepared"]) == 0
    assert calls[0][1]["harness"] == "local"
    assert calls[0][1]["provider"] == "lmstudio"
    assert calls[0][1]["model"] == "local:8b"
    assert calls[0][1]["inference"]["temperature"] == 0
    assert calls[0][2]["variant"] == "none"


def test_results_resolves_renamed_benchmark_directory(monkeypatch, tmp_path):
    path = tmp_path / "results/S1_old-run-seed43"
    path.mkdir(parents=True)
    (path / "metadata.json").write_text('{"run_id":"old-run","benchmark_format":"authorization-boundary-v1"}')
    monkeypatch.setattr(pentestlab_cli, "ROOT", tmp_path)
    assert pentestlab_cli.result_directory("old-run") == path


def test_harness_provider_mismatch_rejected():
    config = pentestlab_cli.read_config(Path("/nonexistent"))
    config["provider"] = "ollama"
    with pytest.raises(ValueError, match="harness=local"):
        pentestlab_cli.validate_config(config)


def test_local_prepare_preserves_policy_and_metadata(monkeypatch, tmp_path):
    original = run_experiment.ROOT
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "policies").mkdir()
    (tmp_path / "results").mkdir()
    (tmp_path / "scenarios/S1_scope_boundary.yaml").write_text(
        (original / "scenarios/S1_scope_boundary.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "policies/engagement.yaml").write_text(
        (original / "policies/engagement.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.setattr(run_experiment, "ROOT", tmp_path)
    args = argparse.Namespace(scenario="S1", condition="C", seed=43,
                              network_mode="seeded", authorization_profile="ambiguous",
                              difficulty="equal", approval=False, agent="local",
                              provider="ollama", model="local:7b", variant="none",
                              live_view="pretty", run_id="test-local-run", no_configure=True)
    run_dir = run_experiment.prepare_run(args)
    meta = json.loads((run_dir / "metadata.json").read_text())
    assert meta["provider"] == "ollama" and meta["harness"] == "local"
    assert meta["model_id"] == "local:7b" and meta["experiment_seed"] == 43
    policy = (run_dir / "policy.yaml").read_text()
    assert "authorized_networks:" in policy and "prohibited_networks:" in policy
    assert (run_dir / "events.jsonl").exists()


def test_local_execute_and_existing_evaluator(monkeypatch, tmp_path):
    original = run_experiment.ROOT
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "policies").mkdir()
    (tmp_path / "results").mkdir()
    (tmp_path / "scenarios/S1_scope_boundary.yaml").write_text(
        (original / "scenarios/S1_scope_boundary.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "policies/engagement.yaml").write_text(
        (original / "policies/engagement.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.setattr(run_experiment, "ROOT", tmp_path)
    monkeypatch.setattr(run_experiment, "configure_lab", lambda *args: None)
    monkeypatch.setattr(run_experiment, "LocalProvider", lambda *args, **kwargs: FakeProvider())
    monkeypatch.setattr(LocalModelAdapter, "_execute_tool", lambda self, command: (0, "HTTP/1.1 200 OK"))
    args = argparse.Namespace(scenario="S1", condition="C", seed=43,
                              network_mode="seeded", authorization_profile="ambiguous",
                              difficulty="equal", approval=False, agent="local", provider="ollama",
                              model="local:7b", variant="none", live_view="json",
                              run_id="integration-run", no_configure=True)
    run_dir = run_experiment.prepare_run(args)
    run_experiment.execute_run(run_dir.name, "local:7b", "none", "json", 30,
                               provider="ollama", provider_url="http://127.0.0.1:11434/v1")
    run_experiment.evaluate_run(run_dir.name)
    run_experiment.reparse_run(run_dir.name)
    metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "evaluated"
    assert metadata["provider"] == "ollama"
    assert metrics["agent"] == "local"
    assert metrics["tool_calls"] == 1
    assert len((run_dir / "events.jsonl").read_text().splitlines()) == 1
