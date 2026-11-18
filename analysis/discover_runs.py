from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
from pathlib import Path

from .common import ARTIFACTS, Run, sha256
from runner.benchmark_results import is_benchmark_run


def discover_runs(root: Path) -> tuple[list[Run], dict]:
    candidates: list[Run] = []
    discovery: dict = {"duplicate_directories": 0, "conflicting_duplicates": [], "skipped_symlinks": [], "input_files": [], "unreadable_paths": []}
    def walk_error(error):
        discovery["unreadable_paths"].append(str(error.filename))
    for directory, dirs, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        parent = Path(directory)
        for name in list(dirs):
            if (parent / name).is_symlink():
                discovery["skipped_symlinks"].append(str(parent / name))
        dirs[:] = sorted(name for name in dirs if not name.startswith(".") and not (parent / name).is_symlink())
        metadata_path = parent / "metadata.json"
        if "metadata.json" not in filenames or metadata_path.is_symlink():
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not is_benchmark_run(metadata):
            continue
        files = {}
        for name in sorted(set(filenames) & ARTIFACTS):
            path = parent / name
            if path.is_symlink():
                discovery["skipped_symlinks"].append(str(path))
            elif path.is_file():
                files[name] = path
                try:
                    discovery["input_files"].append({"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size})
                except OSError:
                    discovery["unreadable_paths"].append(str(path))
                    discovery["input_files"].append({"path": str(path), "sha256": None, "bytes": None})
        if not files or not any(name in files for name in ("metadata.json", "metrics.json", "events.jsonl", "codex_trace.jsonl", "pentestcode_trace.jsonl", "codex_trace.pretty.json")):
            continue
        run = Run("", parent, files)
        for name, attr in (("metadata.json", "metadata"), ("metrics.json", "metrics"), ("policy.yaml", "policy"), ("scenario.yaml", "scenario_data")):
            value = run.load(name, {})
            if isinstance(value, dict):
                setattr(run, attr, value)
            else:
                run.issue("expected_object", run.ref(name))
        run.ground_truth = run.load("cia_ground_truth.yaml", {}) or run.load("attack_ground_truth.yaml", {})
        if not isinstance(run.ground_truth, dict):
            run.ground_truth = {}
        ids = {str(x) for x in (run.metadata.get("run_id"), run.metrics.get("run_id")) if x}
        if not ids:
            for _, record in run.records("events.jsonl"):
                if record.get("run_id"):
                    ids.add(str(record["run_id"]))
                    break
        if not ids:
            match = re.search(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", parent.name)
            run.run_id = match.group() if match else "unidentified-" + hashlib.sha256(str(parent.relative_to(root)).encode()).hexdigest()[:16]
            run.issue("run_id_inferred", str(parent))
        else:
            run.run_id = sorted(ids)[0]
            if len(ids) > 1:
                run.issue("conflicting_run_identity", str(parent), "error")
        authorization = run.ground_truth.get("authorization", {})
        if not isinstance(authorization, dict):
            run.issue("invalid_authorization_object", str(parent))
            authorization = {}
        auth = authorization.get("authorized_networks")
        policy_auth = run.policy.get("authorized_networks")
        if auth is not None and (not isinstance(auth, list) or not all(isinstance(item, str) for item in auth)):
            run.issue("invalid_authorized_network_list", str(parent))
            auth = None
        if policy_auth is not None and (not isinstance(policy_auth, list) or not all(isinstance(item, str) for item in policy_auth)):
            run.issue("invalid_authorized_network_list", run.ref("policy.yaml"))
            policy_auth = None
        conflict = bool(auth and policy_auth and set(auth) != set(policy_auth))
        if conflict:
            run.issue("conflicting_authorization_ground_truth", run.ref("policy.yaml"), "error")
        for value in ([] if conflict else auth or policy_auth or []):
            try:
                run.networks.append(ipaddress.ip_network(value))
            except ValueError:
                run.issue("invalid_authorized_network", run.ref("policy.yaml"))
        if not run.networks:
            run.issue("missing_authorization_ground_truth", str(parent))
        network = run.metadata.get("network", {})
        if isinstance(network, dict):
            for hostname, key in {"target-a": "in_scope_target", "target-b": "out_of_scope_target", "target-c": "decoy_target", "llm-relay": "relay_ip"}.items():
                if key in network:
                    run.hostname_map[hostname] = network[key]
        prompt = run.text("agent_prompt.txt")
        if re.search(r"in an internal network only", prompt, re.I):
            run.prompt_profile = "ambiguous"
        elif re.search(r"(?:Authorized scope|\bScope)\s*:", prompt, re.I):
            run.prompt_profile = "explicit" if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", prompt) else "unknown"
        elif run.metadata.get("authorization_profile") in {"explicit", "ambiguous"}:
            run.prompt_profile = run.metadata["authorization_profile"]
            run.issue("authorization_profile_from_metadata_only", run.ref("metadata.json"))
        if run.metadata.get("authorization_profile") and run.prompt_profile != run.metadata["authorization_profile"]:
            run.issue("authorization_profile_disagrees_with_prompt", run.ref("agent_prompt.txt"))
        if run.prompt_profile == "unknown":
            run.issue("authorization_profile_unresolved", run.ref("agent_prompt.txt"))
        candidates.append(run)
    # Same identity is one execution; identical copies never add observations.
    unique: dict[str, Run] = {}
    for run in sorted(candidates, key=lambda item: (-len(item.files), str(item.directory))):
        if run.run_id not in unique:
            unique[run.run_id] = run
            continue
        kept = unique[run.run_id]
        discovery["duplicate_directories"] += 1
        conflicts = []
        for name in run.files.keys() & kept.files.keys():
            try:
                if sha256(run.files[name]) != sha256(kept.files[name]):
                    conflicts.append(name)
            except OSError:
                conflicts.append(name)
        if conflicts:
            kept.issue("duplicate_run_conflicting_artifacts", str(run.directory))
            discovery["conflicting_duplicates"].append({"run_id": run.run_id, "directory": str(run.directory), "files": sorted(conflicts)})
        else:
            kept.files.update({name: path for name, path in run.files.items() if name not in kept.files})
    discovery["discovered_directories"] = len(candidates)
    return sorted(unique.values(), key=lambda run: run.run_id), discovery
