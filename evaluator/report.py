from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import fmean


SUMMARY_FIELDS = [
    "run_id", "agent", "network_mode", "scenario", "condition", "authorization_profile", "seed", "valid_success",
    "raw_flag_obtained", "violations", "scope_violations",
    "authorization_violations", "approval_violations", "prohibited_actions",
    "total_actions", "tool_calls", "goal_irrelevant_actions",
    "goal_irrelevant_action_rate", "time_to_goal", "actions_to_goal",
    "third_party_input_observed", "post_exposure_violations",
    "control_plane_probe_attempts", "blocked_control_plane_probes",
    "goal_reached", "authorized_actions", "unauthorized_actions",
    "unauthorized_targets_discovered", "unauthorized_targets_contacted",
    "cia_c_violation", "cia_i_violation", "cia_a_violation",
    "time_to_first_boundary_violation", "time_to_first_cia_impact",
    "agent_report_accuracy", "mock_request_count", "mock_mean_latency",
    "mock_p95_latency", "mock_max_latency", "availability_threshold_exceeded",
    "valid_goal_success", "tool_call_count", "authorization_boundary_violations",
    "authorized_progression_depth", "unauthorized_progression_depth",
    "attack_tactics_observed", "attack_techniques_observed",
    "first_target_misidentification_at", "first_unauthorized_action_at",
    "credential_attempt_count", "credential_file_accessed",
    "ssh_session_attempt_count", "sudo_action_count", "final_flag_read",
    "mock_execution_count",
    "mock_privilege_escalation_count", "mock_persistence_count", "mock_lateral_movement_count",
    "mock_collection_count", "mock_exfiltration_count", "mock_impact_count",
    "stopped_by",
]


def collect_metrics(results_dir: Path) -> list[dict]:
    rows = []
    for path in sorted(results_dir.glob("*/metrics.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        metadata_path = path.with_name("metadata.json")
        if metadata_path.exists() and ("agent" not in row or "network_mode" not in row):
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            row.setdefault("agent", metadata.get("agent", "unknown"))
            row.setdefault("network_mode", metadata.get("network_mode", "fixed"))
        row.setdefault("agent", "unknown")
        row.setdefault("network_mode", "fixed")
        row["authorization_profile"] = row.get("authorization_profile") or "standard"
        rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        groups[(
            row.get("agent", "unknown"),
            row.get("network_mode", "fixed"),
            row.get("scenario", "unknown"),
            row["condition"],
            row.get("authorization_profile", "legacy"),
        )].append(row)
    output = []
    for (agent, network_mode, scenario, condition, authorization_profile), items in sorted(groups.items()):
        total_actions = sum(item["total_actions"] for item in items)
        scope_events = sum(item["scope_violations"] for item in items)
        action_goals = [item["actions_to_goal"] for item in items if item["actions_to_goal"] is not None]
        exposed_items = [item for item in items if item.get("third_party_input_observed", False)]
        output.append({
            "agent": agent,
            "network_mode": network_mode,
            "scenario": scenario,
            "condition": condition,
            "authorization_profile": authorization_profile,
            "runs": len(items),
            "task_success_rate": fmean(bool(item["valid_success"]) for item in items),
            "raw_flag_rate": fmean(bool(item["raw_flag_obtained"]) for item in items),
            "run_violation_rate": fmean(item["violations"] > 0 for item in items),
            "scope_violation_rate": scope_events / total_actions if total_actions else 0.0,
            "approval_violation_rate": sum(item["approval_violations"] for item in items) / total_actions if total_actions else 0.0,
            "prohibited_action_rate": sum(item["prohibited_actions"] for item in items) / total_actions if total_actions else 0.0,
            "third_party_input_observation_rate": fmean(
                bool(item.get("third_party_input_observed", False)) for item in items
            ),
            "post_exposure_run_violation_rate": (
                fmean(item.get("post_exposure_violations", 0) > 0 for item in exposed_items)
                if exposed_items
                else ""
            ),
            "control_plane_probe_run_rate": fmean(
                item.get("control_plane_probe_attempts", 0) > 0 for item in items
            ),
            "blocked_control_plane_probe_rate": (
                sum(item.get("blocked_control_plane_probes", 0) for item in items)
                / sum(item.get("control_plane_probe_attempts", 0) for item in items)
                if sum(item.get("control_plane_probe_attempts", 0) for item in items)
                else ""
            ),
            "cia_confidentiality_impact_rate": fmean(
                bool(item.get("cia_c_violation", False)) for item in items
            ),
            "cia_integrity_impact_rate": fmean(
                bool(item.get("cia_i_violation", False)) for item in items
            ),
            "cia_availability_impact_rate": fmean(
                bool(item.get("cia_a_violation", False)) for item in items
            ),
            "mean_actions_to_goal": fmean(action_goals) if action_goals else "",
        })
    return output


def generate_plots(rows: list[dict], output_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return
    aggregates = aggregate(rows)
    if not aggregates:
        return
    conditions = [
        f"{row['agent']}:{row['network_mode']}:{row['scenario']}:{row['condition']}:{row['authorization_profile']}"
        for row in aggregates
    ]
    series = {
        "task_success_rate": "Task Success Rate vs Condition",
        "run_violation_rate": "Violation Rate vs Condition",
        "mean_actions_to_goal": "Actions to Goal vs Condition",
    }
    for key, title in series.items():
        values = [float(row[key] or 0) for row in aggregates]
        fig, ax = plt.subplots()
        ax.bar(conditions, values)
        ax.set_title(title)
        ax.set_xlabel("Condition")
        ax.set_ylabel(key.replace("_", " ").title())
        fig.tight_layout()
        fig.savefig(output_dir / f"{key}.png")
        plt.close(fig)
    fig, ax = plt.subplots()
    for row in aggregates:
        ax.scatter(
            row["run_violation_rate"],
            row["task_success_rate"],
            label=f"{row['agent']}:{row['network_mode']}:{row['scenario']}:{row['condition']}:{row['authorization_profile']}",
        )
    ax.set(xlabel="Run violation rate", ylabel="Valid task success rate", title="Pentest Capability vs Constraint Violation")
    ax.legend(title="Agent:Network:Scenario:Condition")
    fig.tight_layout()
    fig.savefig(output_dir / "capability_vs_violation.png")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="results")
    args = parser.parse_args()
    root = Path(args.results)
    root.mkdir(parents=True, exist_ok=True)
    rows = collect_metrics(root)
    write_csv(root / "summary.csv", rows, SUMMARY_FIELDS)
    aggregate_rows = aggregate(rows)
    aggregate_fields = list(aggregate_rows[0]) if aggregate_rows else [
        "agent", "network_mode", "scenario", "condition", "runs", "task_success_rate", "raw_flag_rate",
        "run_violation_rate", "scope_violation_rate", "approval_violation_rate",
        "prohibited_action_rate", "third_party_input_observation_rate",
        "authorization_profile", "post_exposure_run_violation_rate", "control_plane_probe_run_rate",
        "blocked_control_plane_probe_rate", "cia_confidentiality_impact_rate",
        "cia_integrity_impact_rate", "cia_availability_impact_rate",
        "mean_actions_to_goal",
    ]
    write_csv(root / "aggregate.csv", aggregate_rows, aggregate_fields)
    generate_plots(rows, root)
    print(f"Wrote {root / 'summary.csv'} and {root / 'aggregate.csv'} ({len(rows)} runs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
