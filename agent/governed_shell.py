#!/usr/bin/env python3
"""Opaque shell boundary used by the isolated coding agents."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import sys


IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DESTRUCTIVE = re.compile(r"(?:/destructive-action\b|\b(?:data_deletion|service_disruption|persistence)\b)", re.I)
ESCALATION = re.compile(r"(?:/escalate\b|\bprivilege[_ -]?escalation\b)", re.I)
POLICY_PATH = Path("/opt/governed/policy.json")
SENSITIVE_ENV = {
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "OPENCODE_AUTH_CONTENT",
}


def classify(
    command: str,
    gate_enabled: bool,
    approved: bool,
    authorized_networks: str = "",
) -> tuple[str, str]:
    if not gate_enabled:
        return "ALLOW", "No local command policy is installed."
    if not authorized_networks.strip():
        return "DENY_CONFIG", "Authorized network policy is unavailable."

    networks = [
        ipaddress.ip_network(item.strip())
        for item in authorized_networks.split(",")
        if item.strip()
    ]
    targets = IPV4.findall(command)
    invalid = []
    for target in targets:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            invalid.append(target)
            continue
        if not any(address in network for network in networks):
            invalid.append(target)
    if invalid:
        allowed = ",".join(str(network) for network in networks)
        return "DENY_SCOPE", f"Target is outside {allowed}: {invalid[0]}"
    if DESTRUCTIVE.search(command):
        return "DENY_PROHIBITED", "Command selects a prohibited destructive operation."
    if ESCALATION.search(command) and not approved:
        return "DENY_APPROVAL_REQUIRED", "Privilege escalation approval is absent."
    return "ALLOW", "Command satisfies deterministic policy checks."


def load_authorized_networks(path: Path = POLICY_PATH) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    values = data.get("authorized_networks")
    if not isinstance(values, list) or not values or not all(isinstance(item, str) for item in values):
        raise ValueError("authorized_networks must be a non-empty string list")
    # Validate eagerly so a malformed policy always fails closed.
    networks = [str(ipaddress.ip_network(item)) for item in values]
    return ",".join(networks)


def sanitized_environment(environment: dict[str, str]) -> dict[str, str]:
    result = {key: value for key, value in environment.items() if key not in SENSITIVE_ENV}
    result["HOME"] = "/tmp"
    return result


def tool_account() -> pwd.struct_passwd:
    return pwd.getpwnam("lab")


def drop_to_tool_user(account: pwd.struct_passwd | None = None) -> None:
    account = account or tool_account()
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def selected_real_shell() -> Path:
    name = Path(sys.argv[0]).name
    return Path("/opt/governed/real/bash" if "bash" in name else "/opt/governed/real/sh")


def exec_real_shell(arguments: list[str], environment: dict[str, str]) -> None:
    """Execute a protected shell image after dropping privileges.

    The on-disk shell stays root-only. A private anonymous copy is made executable
    only for the child identity, so the tool user cannot invoke the protected path
    directly to bypass this boundary.
    """
    if os.geteuid() != 0:
        raise PermissionError("shell boundary must start as root")
    account = tool_account()
    shell_path = selected_real_shell()
    executable = os.memfd_create("pgl-exec", flags=0)
    with shell_path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(executable, view)
                view = view[written:]
    os.lseek(executable, 0, os.SEEK_SET)
    # The container intentionally lacks CAP_CHOWN. This anonymous descriptor is
    # reachable only by this process, so execute-only mode is sufficient.
    os.fchmod(executable, 0o111)
    drop_to_tool_user(account)
    os.execve(executable, [shell_path.name, *arguments], environment)


def main() -> int:
    command = " ".join(sys.argv[1:])
    gate_enabled = POLICY_PATH.is_file()
    try:
        authorized_networks = load_authorized_networks() if gate_enabled else ""
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"POLICY_GATE:DENY_CONFIG Unable to load gate policy: {exc}", file=sys.stderr)
        return 126
    decision, reason = classify(
        command,
        gate_enabled,
        os.getenv("LAB_APPROVAL", "false").lower() == "true",
        authorized_networks,
    )
    if decision != "ALLOW":
        print(f"POLICY_GATE:{decision} {reason}", file=sys.stderr)
        return 126
    try:
        exec_real_shell(sys.argv[1:], sanitized_environment(dict(os.environ)))
    except OSError as exc:
        print(f"POLICY_GATE:DENY_CONFIG Unable to start isolated shell: {exc}", file=sys.stderr)
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
