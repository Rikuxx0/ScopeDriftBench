from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import fmean


SUMMARY_FIELDS = [
    "run_id", "scenario", "condition", "seed", "valid_success",
    "raw_flag_obtained", "violations", "scope_violations",
    "authorization_violations", "approval_violations", "prohibited_actions",
    "total_actions", "tool_calls", "goal_irrelevant_actions",
    "goal_irrelevant_action_rate", "time_to_goal", "actions_to_goal",
]


def collect_metrics(results_dir: Path) -> list[dict]:
    rows = []
    for path in sorted(results_dir.glob("*/metrics.json")):
        rows.append(json.loads(path.read_text(encoding="utf-8")))
    return rows


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["condition"]].append(row)
    output = []
    for condition, items in sorted(groups.items()):
        total_actions = sum(item["total_actions"] for item in items)
        scope_events = sum(item["scope_violations"] for item in items)
        action_goals = [item["actions_to_goal"] for item in items if item["actions_to_goal"] is not None]
        output.append({
            "condition": condition,
            "runs": len(items),
            "task_success_rate": fmean(bool(item["valid_success"]) for item in items),
            "raw_flag_rate": fmean(bool(item["raw_flag_obtained"]) for item in items),
            "run_violation_rate": fmean(item["violations"] > 0 for item in items),
            "scope_violation_rate": scope_events / total_actions if total_actions else 0.0,
            "approval_violation_rate": sum(item["approval_violations"] for item in items) / total_actions if total_actions else 0.0,
            "prohibited_action_rate": sum(item["prohibited_actions"] for item in items) / total_actions if total_actions else 0.0,
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
    conditions = [row["condition"] for row in aggregates]
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
        ax.scatter(row["run_violation_rate"], row["task_success_rate"], label=row["condition"])
    ax.set(xlabel="Run violation rate", ylabel="Valid task success rate", title="Pentest Capability vs Constraint Violation")
    ax.legend(title="Condition")
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
        "condition", "runs", "task_success_rate", "raw_flag_rate",
        "run_violation_rate", "scope_violation_rate", "approval_violation_rate",
        "prohibited_action_rate", "mean_actions_to_goal",
    ]
    write_csv(root / "aggregate.csv", aggregate_rows, aggregate_fields)
    generate_plots(rows, root)
    print(f"Wrote {root / 'summary.csv'} and {root / 'aggregate.csv'} ({len(rows)} runs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
