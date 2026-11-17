from runner import environment


def test_doctor_wsl2_no_gpu_no_docker(monkeypatch, tmp_path):
    facts = {"host_os": "Linux", "cpu_architecture": "x86_64", "wsl_version": "2",
             "python_version": "3.12", "docker_engine_version": None,
             "docker_compose_version": None, "gpu": []}
    monkeypatch.setattr(environment, "runtime_environment", lambda root: (facts, {}))
    monkeypatch.setattr(environment, "command", lambda args, timeout=4: None)
    report = environment.doctor(tmp_path, {"provider": "codex_oauth", "model": "x",
                                           "providers": {"ollama": {"base_url": "http://localhost:11434/v1"},
                                                         "lmstudio": {"base_url": "http://localhost:1234/v1"}}})
    checks = {item["name"]: item["status"] for item in report["checks"]}
    assert checks["wsl"] == "PASS"
    assert checks["docker_compose"] == "FAIL"
    assert checks["gpu"] == "WARN"
    assert checks["isolation_healthcheck"] == "SKIP"


def test_doctor_macos_is_not_failed_for_no_wsl(monkeypatch, tmp_path):
    facts = {"host_os": "Darwin", "cpu_architecture": "arm64", "wsl_version": None,
             "python_version": "3.12", "docker_engine_version": "28.0.0",
             "docker_compose_version": "2.36.0", "gpu": []}
    monkeypatch.setattr(environment, "runtime_environment", lambda root: (facts, {}))
    monkeypatch.setattr(environment, "command", lambda args, timeout=4: "")
    report = environment.doctor(tmp_path, {"provider": "codex_oauth", "model": "x",
                                           "providers": {"ollama": {"base_url": "http://localhost:11434/v1"},
                                                         "lmstudio": {"base_url": "http://localhost:1234/v1"}}})
    assert next(item for item in report["checks"] if item["name"] == "wsl")["status"] == "SKIP"


def test_doctor_provider_unavailable_is_warning(monkeypatch, tmp_path):
    facts = {"host_os": "Linux", "cpu_architecture": "x86_64", "wsl_version": "2",
             "python_version": "3.12", "docker_engine_version": None,
             "docker_compose_version": "2.35.0", "gpu": []}
    monkeypatch.setattr(environment, "runtime_environment", lambda root: (facts, {}))
    monkeypatch.setattr(environment, "command", lambda args, timeout=4: None)
    config = {"provider": "ollama", "model": "missing",
              "providers": {"ollama": {"base_url": "http://127.0.0.1:1/v1"},
                            "lmstudio": {"base_url": "http://127.0.0.1:1/v1"}}}
    report = environment.doctor(tmp_path, config, provider="ollama")
    checks = {item["name"]: item["status"] for item in report["checks"]}
    assert checks["docker_compose"] == "FAIL"
    assert checks["provider_ollama"] == "WARN"
