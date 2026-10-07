#!/usr/bin/env python3
"""Run PentestCode's autonomous coordinator and retain all subagent events.

`pentestcode run` normally exits when the root session first becomes idle.  The
upstream `pentest` coordinator can still have asynchronous child sessions at
that point.  This wrapper keeps a headless server alive, attaches the official
CLI to it, and waits until the complete session tree is idle and quiescent.

The experiment prompt is read verbatim from stdin.  JSON lines written to
stdout form the immutable raw trace; operational diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import quote
from urllib.request import urlopen


def emit(record: dict[str, Any], lock: threading.Lock | None = None) -> None:
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    if lock is None:
        print(line, flush=True)
        return
    with lock:
        print(line, flush=True)


def status_event(status: str, **details: Any) -> dict[str, Any]:
    return {
        "type": "harness_status",
        "timestamp": int(time.time() * 1000),
        "status": status,
        **details,
    }


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def api_get(base_url: str, path: str, directory: str) -> Any:
    separator = "&" if "?" in path else "?"
    url = f"{base_url}{path}{separator}directory={quote(directory, safe='')}"
    with urlopen(url, timeout=5) as response:
        return json.load(response)


def wait_for_server(base_url: str, directory: str, process: subprocess.Popen[str], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"PentestCode server exited with status {process.returncode}")
        try:
            api_get(base_url, "/session", directory)
            return
        except Exception as exc:  # the listener may not be ready yet
            error = exc
            time.sleep(0.2)
    raise RuntimeError(f"PentestCode server did not become ready: {error}")


def event_for_part(session_id: str, part: dict[str, Any]) -> dict[str, Any] | None:
    part_type = part.get("type")
    state = part.get("state") if isinstance(part.get("state"), dict) else {}
    if part_type == "tool" and state.get("status") in {"completed", "error"}:
        event_type = "tool_use"
    elif part_type in {"text", "reasoning"} and isinstance(part.get("time"), dict) and part["time"].get("end"):
        event_type = part_type
    elif part_type == "step-start":
        event_type = "step_start"
    elif part_type == "step-finish":
        event_type = "step_finish"
    else:
        return None
    timestamp = None
    if isinstance(part.get("time"), dict):
        timestamp = part["time"].get("end") or part["time"].get("start")
    return {
        "type": event_type,
        "timestamp": timestamp or int(time.time() * 1000),
        "sessionID": session_id,
        "part": part,
    }


def part_key(session_id: str, part: dict[str, Any]) -> tuple[str, str]:
    identifier = part.get("id") or part.get("callID")
    if identifier is None:
        identifier = json.dumps(part, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return session_id, str(identifier)


def completed_parts(messages: Any) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = []
    if not isinstance(messages, list):
        return parts
    for message in messages:
        if not isinstance(message, dict):
            continue
        candidate = message.get("parts", [])
        if isinstance(candidate, list):
            parts.extend(part for part in candidate if isinstance(part, dict))
    return parts


class SessionTreeFollower:
    def __init__(
        self,
        *,
        base_url: str,
        directory: str,
        title: str,
        quiescence: float,
        output_lock: threading.Lock,
    ) -> None:
        self.base_url = base_url
        self.directory = directory
        self.title = title
        self.quiescence = quiescence
        self.output_lock = output_lock
        self.root_id: str | None = None
        self.known_sessions: set[str] = set()
        self.seen_parts: set[tuple[str, str]] = set()
        self.cli_done = threading.Event()
        self.stop = threading.Event()
        self.error: Exception | None = None

    def note_cli_record(self, record: Any) -> bool:
        if not isinstance(record, dict):
            return True
        session_id = record.get("sessionID")
        if isinstance(session_id, str):
            self.root_id = self.root_id or session_id
            self.known_sessions.add(session_id)
        part = record.get("part")
        if isinstance(session_id, str) and isinstance(part, dict):
            key = part_key(session_id, part)
            if key in self.seen_parts:
                return False
            self.seen_parts.add(key)
        return True

    def discover_root(self) -> bool:
        if self.root_id:
            return True
        sessions = api_get(self.base_url, "/session", self.directory)
        if not isinstance(sessions, list):
            return False
        matching = [item for item in sessions if isinstance(item, dict) and item.get("title") == self.title]
        if not matching:
            return False
        root = matching[0].get("id")
        if not isinstance(root, str):
            return False
        self.root_id = root
        self.known_sessions.add(root)
        emit(status_event("coordinator_session", sessionID=root), self.output_lock)
        return True

    def discover_children(self) -> bool:
        changed = False
        pending = list(self.known_sessions)
        visited: set[str] = set()
        while pending:
            session_id = pending.pop()
            if session_id in visited:
                continue
            visited.add(session_id)
            children = api_get(self.base_url, f"/session/{quote(session_id, safe='')}/children", self.directory)
            if not isinstance(children, list):
                continue
            for child in children:
                child_id = child.get("id") if isinstance(child, dict) else None
                if not isinstance(child_id, str):
                    continue
                if child_id not in self.known_sessions:
                    self.known_sessions.add(child_id)
                    changed = True
                    emit(
                        status_event(
                            "subagent_discovered",
                            sessionID=child_id,
                            parentID=session_id,
                            agent=child.get("agent"),
                            title=child.get("title"),
                        ),
                        self.output_lock,
                    )
                pending.append(child_id)
        return changed

    def emit_new_parts(self) -> bool:
        changed = False
        for session_id in sorted(self.known_sessions):
            messages = api_get(
                self.base_url,
                f"/session/{quote(session_id, safe='')}/message",
                self.directory,
            )
            for part in completed_parts(messages):
                event = event_for_part(session_id, part)
                if event is None:
                    continue
                key = part_key(session_id, part)
                if key in self.seen_parts:
                    continue
                self.seen_parts.add(key)
                emit(event, self.output_lock)
                changed = True
        return changed

    def run(self) -> None:
        quiet_since: float | None = None
        last_progress = 0.0
        consecutive_api_errors = 0
        try:
            while not self.stop.is_set():
                try:
                    if not self.discover_root():
                        time.sleep(0.25)
                        continue
                    changed = self.discover_children()
                    changed = self.emit_new_parts() or changed
                    statuses = api_get(self.base_url, "/session/status", self.directory)
                    active = sorted(
                        session_id
                        for session_id in self.known_sessions
                        if isinstance(statuses, dict) and session_id in statuses
                    )
                    consecutive_api_errors = 0
                except Exception as exc:
                    consecutive_api_errors += 1
                    if consecutive_api_errors >= 10:
                        raise RuntimeError(f"lost PentestCode session API: {exc}") from exc
                    time.sleep(0.5)
                    continue

                now = time.monotonic()
                if changed or active or not self.cli_done.is_set():
                    quiet_since = None
                elif quiet_since is None:
                    quiet_since = now

                if now - last_progress >= 10:
                    emit(
                        status_event(
                            "waiting",
                            coordinator=self.root_id,
                            sessions=len(self.known_sessions),
                            activeSessions=len(active),
                        ),
                        self.output_lock,
                    )
                    last_progress = now

                if quiet_since is not None and now - quiet_since >= self.quiescence:
                    emit(
                        status_event(
                            "session_tree_complete",
                            coordinator=self.root_id,
                            sessions=len(self.known_sessions),
                        ),
                        self.output_lock,
                    )
                    return
                time.sleep(0.5)
        except Exception as exc:
            self.error = exc


def pump_server_logs(stream: Any) -> None:
    try:
        for line in iter(stream.readline, ""):
            sys.stderr.write(f"[pentestcode-server] {line}")
            sys.stderr.flush()
    finally:
        stream.close()


def pump_cli_stdout(stream: Any, follower: SessionTreeFollower) -> None:
    try:
        for line in iter(stream.readline, ""):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None
            with follower.output_lock:
                if follower.note_cli_record(record):
                    sys.stdout.write(line)
                    sys.stdout.flush()
    finally:
        stream.close()


def pump_cli_stderr(stream: Any) -> None:
    try:
        for line in iter(stream.readline, ""):
            sys.stderr.write(f"[pentestcode-cli] {line}")
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
    parser.add_argument("--variant", choices=["none", "low", "medium", "high", "xhigh"], default="medium")
    parser.add_argument("--title", required=True)
    parser.add_argument("--directory", default="/workspace")
    parser.add_argument("--agent", default="pentest")
    parser.add_argument("--quiescence", type=float, default=10.0)
    args = parser.parse_args()
    prompt = sys.stdin.read()
    if not prompt:
        parser.error("the experiment prompt must be supplied on stdin")

    port = choose_port()
    base_url = f"http://127.0.0.1:{port}"
    server: subprocess.Popen[str] | None = None
    cli: subprocess.Popen[str] | None = None
    follower: SessionTreeFollower | None = None
    threads: list[threading.Thread] = []
    output_lock = threading.Lock()

    try:
        server = subprocess.Popen(
            ["pentestcode", "serve", "--hostname", "127.0.0.1", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        assert server.stdout is not None
        server_thread = threading.Thread(target=pump_server_logs, args=(server.stdout,), daemon=True)
        server_thread.start()
        threads.append(server_thread)
        wait_for_server(base_url, args.directory, server)
        emit(status_event("server_ready", endpoint=base_url), output_lock)

        follower = SessionTreeFollower(
            base_url=base_url,
            directory=args.directory,
            title=args.title,
            quiescence=args.quiescence,
            output_lock=output_lock,
        )
        cli = subprocess.Popen(
            [
                "pentestcode",
                "run",
                "--attach",
                base_url,
                "--format",
                "json",
                "--agent",
                args.agent,
                "--model",
                args.model,
                "--variant",
                args.variant,
                "--auto",
                "--dir",
                args.directory,
                "--title",
                args.title,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        assert cli.stdin is not None
        assert cli.stdout is not None
        assert cli.stderr is not None
        cli.stdin.write(prompt)
        cli.stdin.close()
        emit(
            status_event(
                "coordinator_started",
                agent=args.agent,
                model=args.model,
                variant=args.variant,
            ),
            output_lock,
        )

        stdout_thread = threading.Thread(target=pump_cli_stdout, args=(cli.stdout, follower), daemon=True)
        stderr_thread = threading.Thread(target=pump_cli_stderr, args=(cli.stderr,), daemon=True)
        follow_thread = threading.Thread(target=follower.run, daemon=True)
        for thread in (stdout_thread, stderr_thread, follow_thread):
            thread.start()
            threads.append(thread)

        returncode = cli.wait()
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        follower.cli_done.set()
        follow_thread.join()
        if follower.error is not None:
            raise follower.error
        if returncode != 0:
            raise RuntimeError(f"PentestCode coordinator exited with status {returncode}")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"autonomous runner error: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if follower is not None:
            follower.stop.set()
        terminate(cli)
        terminate(server)
        for thread in threads:
            thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
