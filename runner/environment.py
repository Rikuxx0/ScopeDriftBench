"""Best-effort, read-only host facts for diagnostics and reproducibility."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def command(args: list[str], timeout: int = 4) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def gpu_info() -> list[dict]:
    output = command(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
    if output:
        return [{"vendor": "NVIDIA", "model": parts[0], "vram_bytes": int(parts[1]) * 1024 * 1024,
                 "driver_version": parts[2]} for line in output.splitlines()
                if len(parts := [p.strip() for p in line.split(",")]) == 3 and parts[1].isdigit()]
    output = command(["lspci", "-mm"])
    if output:
        return [{"vendor": vendor, "model": line, "vram_bytes": None, "driver_version": None}
                for line in output.splitlines() for vendor in ("AMD", "NVIDIA", "Intel")
                if ("VGA" in line or "3D controller" in line) and vendor.lower() in line.lower()]
    return []


def runtime_environment(root: Path) -> tuple[dict, dict]:
    errors: dict[str, str] = {}
    system = platform.system()
    kernel = platform.release()
    wsl = "2" if system == "Linux" and "microsoft" in kernel.lower() and "wsl2" in kernel.lower() else (
        "1" if system == "Linux" and "microsoft" in kernel.lower() else None)
    ram = None
    try:
        if system == "Linux":
            ram = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text()).group(1)) * 1024
        elif system == "Darwin":
            value = command(["sysctl", "-n", "hw.memsize"])
            ram = int(value) if value else None
    except (OSError, AttributeError, ValueError) as exc:
        errors["system_ram_bytes"] = type(exc).__name__
    cpu_model = None
    try:
        if system == "Linux":
            cpu_model = re.search(r"model name\s*:\s*(.+)", Path("/proc/cpuinfo").read_text()).group(1)
        elif system == "Darwin":
            cpu_model = command(["sysctl", "-n", "machdep.cpu.brand_string"])
    except (OSError, AttributeError) as exc:
        errors["cpu_model"] = type(exc).__name__
    engine = command(["docker", "version", "--format", "{{.Server.Version}}"])
    compose = command(["docker", "compose", "version", "--short"])
    if not engine: errors["docker_engine_version"] = "unavailable"
    if not compose: errors["docker_compose_version"] = "unavailable"
    try:
        free = shutil.disk_usage(root).free
    except OSError as exc:
        free = None
        errors["disk_free_bytes"] = type(exc).__name__
    data = {"host_os": system, "host_os_version": platform.version() if not wsl else None,
            "wsl_version": wsl, "linux_kernel": kernel if system == "Linux" else None,
            "cpu_architecture": platform.machine(), "cpu_model": cpu_model,
            "system_ram_bytes": ram, "gpu": gpu_info(),
            "docker_engine_version": engine, "docker_compose_version": compose,
            "python_version": platform.python_version(), "disk_free_bytes": free}
    return data, errors


def doctor(root: Path, config: dict, *, provider: str | None = None, model_id: str | None = None,
           full: bool = False, test_tool_calling: bool = False) -> dict:
    from runner.providers import LocalProvider, ProviderError
    env, errors = runtime_environment(root)
    checks = []
    def add(name: str, status: str, detail: str = "") -> None:
        checks.append({"name": name, "status": status, "detail": detail})
    add("platform", "PASS", f"{env['host_os']} {env['cpu_architecture']} WSL={env['wsl_version'] or 'none'}")
    add("python", "PASS" if sys.version_info >= (3, 12) else "FAIL", env["python_version"])
    add("docker_engine", "PASS" if env["docker_engine_version"] else "FAIL", str(env["docker_engine_version"]))
    version = env["docker_compose_version"]
    parts = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version or "")
    add("docker_compose", "PASS" if parts and tuple(map(int, parts.groups())) >= (2, 36, 0) else "FAIL",
        f"{version or 'unavailable'}; interface_name requires 2.36.0+")
    if env["wsl_version"]:
        add("wsl", "PASS" if env["wsl_version"] == "2" else "FAIL", env["wsl_version"])
        info = command(["docker", "info", "--format", "{{.OperatingSystem}}"])
        add("docker_desktop_wsl", "PASS" if info and "Docker Desktop" in info else "UNKNOWN", info or "backend cannot be established")
    else:
        add("wsl", "SKIP", "Not running in WSL")
    add("gpu", "PASS" if env["gpu"] else "WARN", json.dumps(env["gpu"]) if env["gpu"] else "No GPU detected; CPU inference may be possible")
    if env["wsl_version"] == "2":
        add("wsl_gpu", "PASS" if env["gpu"] else "UNKNOWN", "GPU visibility is not proof of provider acceleration")
    compose_script = root / "scripts/compose.sh"
    if version and env["docker_engine_version"]:
        configured = (root / ".generated/network.env").is_file()
        output = command([str(compose_script), "config", "--quiet"]) if configured else None
        add("compose_config", "PASS" if output is not None else "FAIL" if configured else "SKIP",
            "docker compose config --quiet" if configured else "Generated network config absent; read-only doctor did not create it")
        running = command([str(compose_script), "ps", "--status", "running", "--services"]) if configured else None
        services = set((running or "").splitlines())
        active = {"pentestcode", "pentestcode-gated", "codex", "codex-gated", "llm-relay", "collector", "target-a", "target-b"} <= services
        add("lab_running", "PASS" if active else "SKIP", "Live isolation unverified" if not active else "Required services running")
        if active and full and (root / "results/.active_run").is_file():
            add("isolation_healthcheck", "SKIP", "Active run present; healthcheck could affect tool budget")
        elif active and full:
            try:
                result = subprocess.run([str(root / "scripts/healthcheck.sh")], cwd=root, capture_output=True, text=True, timeout=120, check=False)
                add("isolation_healthcheck", "PASS" if result.returncode == 0 else "FAIL", (result.stdout + result.stderr)[-2500:])
            except (OSError, subprocess.TimeoutExpired) as exc:
                add("isolation_healthcheck", "FAIL", type(exc).__name__)
        else:
            add("isolation_healthcheck", "SKIP", "Use --full with a running lab")
    else:
        add("compose_config", "SKIP", "Docker unavailable")
        add("lab_running", "SKIP", "Docker unavailable")
        add("isolation_healthcheck", "SKIP", "Docker unavailable")
    for selected_provider in ([provider] if provider else ["ollama", "lmstudio"]):
        try:
            rows = LocalProvider(selected_provider, config["providers"][selected_provider]["base_url"], timeout=4).list_models()
            add(f"provider_{selected_provider}", "PASS", f"{len(rows)} models")
            selected_model = model_id or (config["model"] if config["provider"] == selected_provider else None)
            model = next((item for item in rows if item.model_id == selected_model), None) if selected_model else None
            if selected_model:
                add("model", "PASS" if model else "FAIL", str(model.as_dict()) if model else "Configured model not listed")
            if model:
                add("tool_calling", "PASS" if model.tool_calling else "FAIL" if model.tool_calling is False else "UNKNOWN", str(model.tool_calling))
                add("model_loaded", "FAIL" if model.loaded is False else "PASS" if model.loaded else "UNKNOWN", str(model.loaded))
                if test_tool_calling and model.loaded is not False:
                    try:
                        probe = LocalProvider(selected_provider, config["providers"][selected_provider]["base_url"], timeout=30)
                        answer = probe.infer(model.model_id,
                            [{"role": "user", "content": "Call the report_ready tool with ready=true. Do not use other tools."}],
                            [{"type": "function", "function": {"name": "report_ready", "description": "Report readiness only",
                              "parameters": {"type": "object", "properties": {"ready": {"type": "boolean"}}, "required": ["ready"]}}}])
                        calls = answer["message"].get("tool_calls") or []
                        add("tool_call_probe", "PASS" if any(isinstance(c, dict) and c.get("function", {}).get("name") == "report_ready" for c in calls) else "FAIL",
                            "Synthetic tool declaration; no tool was executed")
                    except ProviderError as exc:
                        add("tool_call_probe", "FAIL", str(exc))
        except (ProviderError, ValueError, OSError) as exc:
            add(f"provider_{selected_provider}", "WARN", str(exc))
    return {"runtime_environment": env, "collection_errors": errors, "checks": checks}
