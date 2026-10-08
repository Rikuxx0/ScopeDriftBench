#!/usr/bin/env python3
"""Run Codex CLI headlessly and emit a timestamped immutable JSONL trace."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any


def emit(record: dict[str, Any], lock: threading.Lock) -> None:
    record.setdefault("timestamp", int(time.time() * 1000))
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    with lock:
        print(line, flush=True)


def pump_stdout(stream: Any, lock: threading.Lock) -> None:
    try:
        for line in iter(stream.readline, ""):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = {"type": "codex_stdout", "text": line.rstrip("\n")}
            emit(record, lock)
    finally:
        stream.close()


def pump_stderr(stream: Any) -> None:
    try:
        for line in iter(stream.readline, ""):
            sys.stderr.write(f"[codex-cli] {line}")
            sys.stderr.flush()
    finally:
        stream.close()


def terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--variant",
        choices=["none", "low", "medium", "high", "xhigh"],
        default="medium",
    )
    parser.add_argument("--directory", default="/workspace")
    args = parser.parse_args()
    prompt = sys.stdin.read()
    if not prompt:
        parser.error("the experiment prompt must be supplied on stdin")

    command = [
        "codex",
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        # The lab exposes only the local shell tool. Workspace apps and plugin
        # catalogs are unrelated to the experiment and their discovery calls
        # are deliberately not allowlisted by the provider relay.
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "remote_plugin",
        "--model",
        args.model,
        "--config",
        f'model_reasoning_effort="{args.variant}"',
        # The relay is an HTTP allowlist, not a generic WebSocket proxy. The
        # built-in ``openai`` provider is immutable, so use an ephemeral custom
        # provider with the same ChatGPT OAuth endpoint and HTTP transport.
        "--config",
        'model_provider="lab_openai_http"',
        "--config",
        'model_providers.lab_openai_http.name="Lab OpenAI HTTPS"',
        "--config",
        'model_providers.lab_openai_http.base_url="https://chatgpt.com/backend-api/codex"',
        "--config",
        'model_providers.lab_openai_http.wire_api="responses"',
        "--config",
        "model_providers.lab_openai_http.requires_openai_auth=true",
        "--config",
        "model_providers.lab_openai_http.supports_websockets=false",
        "--cd",
        args.directory,
        "-",
    ]
    lock = threading.Lock()
    process: subprocess.Popen[str] | None = None
    threads: list[threading.Thread] = []
    try:
        emit(
            {
                "type": "harness_status",
                "status": "coordinator_started",
                "agent": "codex",
                "model": args.model,
                "variant": args.variant,
            },
            lock,
        )
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_thread = threading.Thread(target=pump_stdout, args=(process.stdout, lock), daemon=True)
        stderr_thread = threading.Thread(target=pump_stderr, args=(process.stderr,), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        threads.extend((stdout_thread, stderr_thread))
        process.stdin.write(prompt)
        process.stdin.close()
        returncode = process.wait()
        for thread in threads:
            thread.join(timeout=5)
        emit(
            {
                "type": "harness_status",
                "status": "completed" if returncode == 0 else "failed",
                "returncode": returncode,
            },
            lock,
        )
        return returncode
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"codex runner error: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        terminate(process)
        for thread in threads:
            thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
