from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .common import sha256


def validate_tables(tables: dict[str, list[dict]]) -> list[dict]:
    problems = []
    ids = [row["run_id"] for row in tables["runs"]]
    if len(set(ids)) != len(ids):
        problems.append({"code": "duplicate_run_rows", "severity": "error"})
    duration = {row["run_id"]: row.get("execution_duration_seconds") for row in tables["runs"]}
    previous = {}
    for row in tables["timeseries"]:
        key = row["run_id"]
        for field in ("cumulative_actions", "cumulative_requests", "cumulative_in_scope_requests", "cumulative_out_of_scope_requests", "cumulative_unknown_scope_requests", "cumulative_tcp_connections"):
            value = row.get(field)
            old = previous.get((key, field))
            if value not in (None, ""):
                value = float(value)
                if value < 0 or (old is not None and value < old):
                    problems.append({"run_id": key, "code": "nonmonotonic_series", "field": field, "severity": "error"})
                previous[key, field] = value
        seconds = float(row["elapsed_seconds"])
        end = duration.get(key)
        if seconds < 0 or (end not in (None, "") and seconds > float(end) + 1e-5):
            problems.append({"run_id": key, "code": "series_outside_execution", "severity": "error"})
    for row in tables["network_events"]:
        if row["execution_status"] == "blocked" and row.get("request_count") not in (None, ""):
            problems.append({"run_id": row["run_id"], "code": "blocked_network_counted", "severity": "error"})
    for row in tables["milestones"]:
        if row.get("occurred") in (False, "false", "") and row.get("elapsed_seconds") not in (None, ""):
            problems.append({"run_id": row["run_id"], "code": "absent_milestone_has_time", "severity": "error"})
    return problems


def quality_report(runs: list, tables: dict[str, list[dict]], discovery: dict, failures: list[dict], dedup: dict) -> dict:
    table_issues = validate_tables(tables)
    rows = tables["runs"]
    by_scenario = Counter(row.get("scenario") or "unknown" for row in rows)
    by_profile = Counter(row.get("authorization_profile") or "unknown" for row in rows)
    conflicts = {run.run_id for run in runs if any("disagree" in item["code"] or "conflict" in item["code"] or "metric_mismatch" in item["code"] for item in run.issues)}
    missing_fields = ["execution_duration_seconds", "time_to_goal", "time_to_first_boundary_violation", "time_to_first_cia_impact", "first_boundary_violation_turn_index", "total_observed_network_requests"]
    return {
        "discovered_run_directories": discovery["discovered_directories"],
        "discovered_runs": len(runs),
        "processed_runs": len(rows) - len(failures),
        "fully_processed_runs": sum(row["validation_status"] == "ok" for row in rows),
        "partially_processed_runs": sum(row["validation_status"] not in {"ok", "collection_failed"} for row in rows),
        "failed_runs": failures,
        "scenario_counts": dict(sorted(by_scenario.items())),
        "authorization_profile_counts": dict(sorted(by_profile.items())),
        "runs_with_execution_timestamps": sum(row.get("execution_duration_seconds") is not None for row in rows),
        "runs_with_observed_http_counts": sum(row.get("total_observed_network_requests") is not None for row in rows),
        "runs_with_partial_network_observation": sum(str(row.get("request_coverage", "")).startswith("partial") for row in rows),
        "runs_with_metric_inconsistencies": len(conflicts),
        "deduplication": dict(dedup, duplicate_directories=discovery["duplicate_directories"], conflicting_duplicates=discovery["conflicting_duplicates"]),
        "skipped_symlinks": discovery["skipped_symlinks"],
        "unreadable_paths": discovery["unreadable_paths"],
        "missing_metric_counts": {field: sum(row.get(field) is None for row in rows) for field in missing_fields},
        "issue_counts": dict(sorted(Counter(item["code"] for run in runs for item in run.issues).items())),
        "run_issues": [{"run_id": run.run_id, "issues": run.issues} for run in runs if run.issues],
        "table_validation_issues": table_issues,
        "interpretation": {
            "missing": "Empty CSV cells mean unknown or not observed, never an assumed zero.",
            "network": "HTTP requests, admitted requests, TCP connections and scanner actions are separate units. Counts are partial lower bounds.",
            "time": "Untimed service totals are not allocated to the timeline. Client response batches use tool completion as an upper time bound.",
            "authorization": "Ground-truth authorization is independent of the prompt and of agent self-reports.",
            "causality": "Temporal association does not establish causality.",
        },
    }


def validate_output(directory: Path) -> tuple[dict, list[dict]]:
    tables = {}
    for name in ("runs", "actions", "network_events", "milestones", "timeseries"):
        path = directory / f"{name}.csv"
        if path.is_symlink():
            raise ValueError(f"Refusing output symlink: {path}")
        with path.open(encoding="utf-8", newline="") as handle:
            tables[name] = list(csv.DictReader(handle))
    issues = validate_tables(tables)
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Refusing manifest symlink")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("outputs", []):
        path = directory / Path(entry["path"]).name
        if path.is_symlink() or not path.is_file() or sha256(path) != entry["sha256"]:
            issues.append({"code": "output_checksum_mismatch", "file": path.name, "severity": "error"})
    return {name: len(rows) for name, rows in tables.items()}, issues
