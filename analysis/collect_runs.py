from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

from .build_timeseries import TIMESERIES_FIELDS, build_timeseries
from .collect_events import ACTION_FIELDS, collect_events
from .collect_milestones import MILESTONE_FIELDS, collect_milestones
from .collect_network import NETWORK_FIELDS, collect_network
from .common import ROOT, VERSION, Run, execution_duration, iso, sha256, write_csv, write_json
from .discover_runs import discover_runs
from .validate_data import quality_report, validate_output


RUN_FIELDS = "run_id scenario condition seed agent network_mode authorization_profile execution_status execution_duration_seconds valid_success raw_flag_obtained total_actions tool_calls authorized_actions unauthorized_actions scope_violations time_to_goal time_to_first_boundary_violation time_to_first_cia_impact cia_c_violation cia_i_violation cia_a_violation mock_request_count stopped_by first_boundary_violation_action_index first_boundary_violation_turn_index total_observed_network_requests in_scope_network_requests out_of_scope_network_requests unknown_scope_network_requests data_completeness validation_status request_coverage network_request_unit execution_start execution_end time_origin first_unauthorized_contact_seconds boundary_to_impact_seconds reported_valid_success reported_valid_goal_success reported_scope_violations reported_total_actions reported_tool_calls reported_tool_call_count reported_time_to_goal reported_time_to_first_boundary_violation reported_time_to_first_cia_impact model model_variant run_directory".split()


def summarize(run: Run, actions: list[dict], network: list[dict], milestones: list[dict], info: dict, net_info: dict) -> dict:
    by_type = {row["event_type"]: row for row in milestones}
    goal = by_type["valid_goal_reached"]
    boundary = by_type["first_executed_boundary_violation"]
    impact_rows = [by_type["first_" + dimension + "_impact"] for dimension in ("confidentiality", "integrity", "availability")]
    impact_times = [row["elapsed_seconds"] for row in impact_rows if row["occurred"] and row["elapsed_seconds"] is not None]
    impact_time = min(impact_times) if impact_times else None
    groups = {}
    for row in actions:
        groups.setdefault(row["action_index"], []).append(row)
    scopes = []
    for group in groups.values():
        values = {row["target_scope"] for row in group}
        scopes.append("out_of_scope" if values & {"out_of_scope", "mixed"} else "in_scope" if values == {"in_scope"} else "unknown")
    violating = {row["action_index"] for row in actions if row["boundary_violation"] is True}
    executed_violating = {row["action_index"] for row in actions if row["boundary_violation"] is True and row["execution_status"] == "executed"}
    metric = run.metrics
    # Values are reconstructed from evidence; legacy fields are preserved separately.
    comparisons = (("valid_success", "valid_goal_success"), ("violations", "authorization_boundary_violations"), ("tool_calls", "tool_call_count"))
    for first, second in comparisons:
        if first in metric and second in metric and metric[first] != metric[second]:
            run.issue(f"metric_mismatch_{first}_{second}", run.ref("metrics.json"))
    if "valid_success" in metric and goal["occurred"] is not None and metric["valid_success"] != goal["occurred"]:
        run.issue("metric_mismatch_valid_success_observed", run.ref("metrics.json"))
    if "scope_violations" in metric and metric["scope_violations"] != len(violating):
        run.issue("metric_mismatch_scope_violations_normalized", run.ref("metrics.json"))
    if "total_actions" in metric and actions and metric["total_actions"] != len(groups):
        run.issue("metric_mismatch_total_actions_observed", run.ref("metrics.json"))
    if "tool_calls" in metric and info["tool_calls"] is not None and metric["tool_calls"] != info["tool_calls"]:
        run.issue("metric_mismatch_tool_calls_observed", run.ref("metrics.json"))
    totals = net_info["http_totals"]
    counts = {scope: sum(row["request_count"] for row in totals if (row["target_scope"] if row["target_scope"] in {"in_scope", "out_of_scope"} else "unknown") == scope) for scope in ("in_scope", "out_of_scope", "unknown")}
    lifecycle = info.get("lifecycle", [])
    status = run.metadata.get("status", "unknown")
    stopped_by = run.metadata.get("safety_stop_reason") or info.get("stop_reason") or metric.get("stopped_by")
    if stopped_by is None and any(row["type"] == "turn.failed" for row in lifecycle):
        stopped_by = "agent_turn_failed"
    if stopped_by is None and status == "interrupted":
        stopped_by = "interrupted"
    if stopped_by is None and any(row["type"] == "turn.completed" for row in lifecycle):
        stopped_by = "agent_turn_completed"
    contact = by_type["first_unauthorized_contact"]["elapsed_seconds"]
    components = {"identity": bool(run.metadata.get("run_id")), "authorization": bool(run.networks), "actions": bool(actions), "execution_time": execution_duration(run) is not None, "http_observation": bool(totals)}
    row = {
        "run_id": run.run_id, "scenario": run.scenario, "condition": run.metadata.get("condition", metric.get("condition")), "seed": run.metadata.get("seed", metric.get("seed")), "agent": run.metadata.get("agent", metric.get("agent")), "network_mode": run.metadata.get("network_mode", metric.get("network_mode")), "authorization_profile": run.prompt_profile,
        "execution_status": status, "execution_duration_seconds": execution_duration(run),
        "valid_success": goal["occurred"], "raw_flag_obtained": getattr(run, "_raw_flag", None), "total_actions": len(groups) if actions else None, "tool_calls": info["tool_calls"],
        "authorized_actions": scopes.count("in_scope") if actions and run.networks else None, "unauthorized_actions": len(executed_violating) if actions and run.networks else None, "scope_violations": len(violating) if actions and run.networks else None,
        "time_to_goal": goal["elapsed_seconds"], "time_to_first_boundary_violation": boundary["elapsed_seconds"], "time_to_first_cia_impact": impact_time,
        "cia_c_violation": impact_rows[0]["occurred"], "cia_i_violation": impact_rows[1]["occurred"], "cia_a_violation": impact_rows[2]["occurred"],
        "mock_request_count": net_info["telemetry"].get("request_count"), "stopped_by": stopped_by,
        "first_boundary_violation_action_index": boundary["action_index"], "first_boundary_violation_turn_index": boundary["turn_index"],
        "total_observed_network_requests": sum(counts.values()) if totals else None,
        "in_scope_network_requests": counts["in_scope"] if totals else None, "out_of_scope_network_requests": counts["out_of_scope"] if totals else None, "unknown_scope_network_requests": counts["unknown"] if totals else None,
        "data_completeness": ";".join(key for key, value in components.items() if value), "validation_status": "review_required" if any(issue["severity"] == "error" for issue in run.issues) else "partial" if run.issues else "ok",
        "request_coverage": net_info["coverage"], "network_request_unit": "http_requests_partial_lower_bound",
        "execution_start": iso(run.start), "execution_end": iso(run.end), "time_origin": run.time_origin,
        "first_unauthorized_contact_seconds": contact,
        "boundary_to_impact_seconds": round(impact_time - boundary["elapsed_seconds"], 6) if impact_time is not None and boundary["elapsed_seconds"] is not None and impact_time >= boundary["elapsed_seconds"] else None,
        "model": run.metadata.get("model"), "model_variant": run.metadata.get("model_variant"), "run_directory": str(run.directory),
    }
    for field in RUN_FIELDS:
        if field.startswith("reported_"):
            row[field] = metric.get(field.removeprefix("reported_"))
    return row


def collect(results_dir: Path, output_dir: Path, bin_seconds: float = 10, dry_run: bool = False) -> dict:
    runs, discovery = discover_runs(results_dir)
    if dry_run:
        return {"dry_run": True, "discovered_runs": len(runs), "scenario_counts": dict(Counter(run.scenario or "unknown" for run in runs)), "duplicate_directories": discovery["duplicate_directories"]}
    tables = {name: [] for name in ("runs", "actions", "network_events", "milestones", "timeseries")}
    failures = []
    dedup = {"action_records_merged_or_removed": 0, "network_records_suppressed": 0}
    for run in runs:
        stage = "actions"
        try:
            actions, messages, info = collect_events(run)
            stage = "network"
            network, net_info = collect_network(run, actions)
            stage = "milestones"
            milestones = collect_milestones(run, actions, network, messages, net_info, info)
            stage = "timeseries"
            series = build_timeseries(run, actions, network, milestones, net_info["coverage"], bin_seconds)
            stage = "run_summary"
            summary = summarize(run, actions, network, milestones, info, net_info)
            tables["runs"].append(summary)
            for name, rows in (("actions", actions), ("network_events", network), ("milestones", milestones), ("timeseries", series)):
                tables[name].extend({key: value for key, value in row.items() if not key.startswith("_")} for row in rows)
            dedup["action_records_merged_or_removed"] += info["duplicates"]
            dedup["network_records_suppressed"] += net_info["duplicates"]
        except Exception as exc:
            # Never serialize exception text: it may contain a raw log or secret.
            failures.append({"run_id": run.run_id, "directory": str(run.directory), "stage": stage, "reason": type(exc).__name__})
            run.issue("run_processing_failed", str(run.directory), "error")
            tables["runs"].append({"run_id": run.run_id, "scenario": run.scenario, "condition": run.metadata.get("condition"), "seed": run.metadata.get("seed"), "agent": run.metadata.get("agent"), "network_mode": run.metadata.get("network_mode"), "authorization_profile": run.prompt_profile, "execution_status": run.metadata.get("status", "unknown"), "validation_status": "collection_failed", "data_completeness": "identity_only", "request_coverage": "unmeasured", "run_directory": str(run.directory)})
    report = quality_report(runs, tables, discovery, failures, dedup)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, fields in (("runs", RUN_FIELDS), ("actions", ACTION_FIELDS), ("network_events", NETWORK_FIELDS), ("milestones", MILESTONE_FIELDS), ("timeseries", TIMESERIES_FIELDS)):
        write_csv(output_dir / f"{name}.csv", tables[name], fields)
    write_json(output_dir / "quality_report.json", report)
    outputs = [{"path": name, "sha256": sha256(output_dir / name)} for name in ("runs.csv", "actions.csv", "network_events.csv", "milestones.csv", "timeseries.csv", "quality_report.json")]
    code_files = sorted(Path(__file__).parent.glob("*.py")) + [ROOT / "collect_research_data.sh"]
    write_json(output_dir / "manifest.json", {"collector_version": VERSION, "results_dir": str(results_dir), "bin_seconds": bin_seconds, "python_version": sys.version.split()[0], "inputs": sorted(discovery["input_files"], key=lambda entry: entry["path"]), "collector_sources": [{"path": str(path.relative_to(ROOT)), "sha256": sha256(path)} for path in code_files], "outputs": outputs, "rows": {name: len(rows) for name, rows in tables.items()}})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect existing experiment evidence into research CSVs without executing agents or scans.")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "analysis/output")
    parser.add_argument("--bin-seconds", type=float, default=10)
    parser.add_argument("--dry-run", action="store_true", help="Discover runs and report counts; write nothing.")
    parser.add_argument("--validate-only", action="store_true", help="Validate existing output tables and checksums; write nothing.")
    args = parser.parse_args(argv)
    if not math.isfinite(args.bin_seconds) or args.bin_seconds <= 0:
        parser.error("--bin-seconds must be positive")
    if args.results_dir.is_symlink() or any(parent.is_symlink() for parent in args.results_dir.parents):
        parser.error("results path may not contain symlinks")
    if args.output_dir.is_symlink() or any(parent.is_symlink() for parent in args.output_dir.parents):
        parser.error("output path may not contain symlinks")
    results = args.results_dir.resolve()
    output = args.output_dir.resolve()
    if output == results or results in output.parents or output in results.parents:
        parser.error("input and output directories must not contain each other")
    try:
        if args.validate_only:
            counts, issues = validate_output(output)
            print(json.dumps({"rows": counts, "validation_issues": issues}, ensure_ascii=False, sort_keys=True))
            return 1 if issues else 0
        if not results.is_dir():
            parser.error("--results-dir is not a directory")
        report = collect(results, output, args.bin_seconds, args.dry_run)
        print(json.dumps({key: report[key] for key in ("dry_run", "discovered_runs", "processed_runs", "partially_processed_runs", "failed_runs", "scenario_counts") if key in report}, ensure_ascii=False, sort_keys=True))
        if not args.dry_run:
            print(f"Output: {output}")
        return 1 if report.get("table_validation_issues") else 0
    except (OSError, ValueError) as exc:
        print(f"Collection failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
