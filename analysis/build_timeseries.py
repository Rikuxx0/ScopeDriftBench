from __future__ import annotations

import math

from .common import Run, execution_duration


TIMESERIES_FIELDS = "run_id scenario elapsed_seconds row_type cumulative_actions cumulative_requests cumulative_in_scope_requests cumulative_out_of_scope_requests cumulative_unknown_scope_requests boundary_violation_observed impact_observed request_coverage series_unit timing_precision cumulative_port_scan_actions cumulative_host_discovery_actions cumulative_tcp_connections cumulative_scan_address_targets cumulative_reported_live_hosts".split()


def build_timeseries(run: Run, actions: list[dict], network: list[dict], milestones: list[dict], coverage: str, bin_seconds: float) -> list[dict]:
    duration = execution_duration(run)
    if duration is None:
        return []
    if duration < 0:
        run.issue("invalid_execution_duration", run.ref("metadata.json"))
        return []
    if duration / bin_seconds > 1_000_000:
        run.issue("timeseries_bin_limit_exceeded", str(run.directory))
        return []
    timed_http = [row for row in network if row["request_type"] == "http_requests" and row["included_in_totals"] and row["execution_status"] == "observed" and row["request_count"] is not None and row["elapsed_seconds"] is not None]
    tcp = [row for row in network if row["request_type"] == "tcp_connections" and row["included_in_totals"] and row["execution_status"] == "observed" and row["request_count"] is not None and row["elapsed_seconds"] is not None]
    scanner = [row for row in network if row["evidence_source"] == "scanner_summary" and row["elapsed_seconds"] is not None and row["elapsed_seconds"] >= 0]
    # A total without request timestamps is never spread or jumped at run end.
    event_times = {0.0, duration}
    for row in actions + timed_http + tcp + scanner + milestones:
        value = row.get("elapsed_seconds")
        if value is not None and 0 <= value <= duration:
            event_times.add(value)
    times = set(event_times)
    times.update(round(index * bin_seconds, 6) for index in range(1, math.floor(duration / bin_seconds) + 1))
    actions_by_index = {}
    for row in actions:
        actions_by_index.setdefault(row["action_index"], row)
    ordered_actions = sorted([row for row in actions_by_index.values() if row["elapsed_seconds"] is not None and row["elapsed_seconds"] >= 0], key=lambda row: row["elapsed_seconds"])
    http = sorted([row for row in timed_http if row["elapsed_seconds"] >= 0], key=lambda row: row["elapsed_seconds"])
    tcp.sort(key=lambda row: row["elapsed_seconds"])
    first_boundary = next((row["elapsed_seconds"] for row in milestones if row["event_type"] == "first_executed_boundary_violation" and row["occurred"]), None)
    impacts = [row["elapsed_seconds"] for row in milestones if row["event_type"] in {"first_confidentiality_impact", "first_integrity_impact", "first_availability_impact"} and row["occurred"] and row["elapsed_seconds"] is not None]
    impact = min(impacts) if impacts else None
    counts = {"in_scope": 0, "out_of_scope": 0, "unknown": 0}
    action_cursor = http_cursor = tcp_cursor = 0
    scan_count = host_count = tcp_count = 0
    rows = []
    for seconds in sorted(times):
        while action_cursor < len(ordered_actions) and ordered_actions[action_cursor]["elapsed_seconds"] <= seconds:
            action = ordered_actions[action_cursor]
            if action["execution_status"] == "executed":
                scan_count += action["action_type"] == "port_scan"
                host_count += action["action_type"] == "host_discovery"
            action_cursor += 1
        while http_cursor < len(http) and http[http_cursor]["elapsed_seconds"] <= seconds:
            row = http[http_cursor]
            counts[row["target_scope"] if row["target_scope"] in counts else "unknown"] += row["request_count"]
            http_cursor += 1
        while tcp_cursor < len(tcp) and tcp[tcp_cursor]["elapsed_seconds"] <= seconds:
            tcp_count += tcp[tcp_cursor]["request_count"]
            tcp_cursor += 1
        binned = abs(seconds / bin_seconds - round(seconds / bin_seconds)) < 1e-7
        rows.append({"run_id": run.run_id, "scenario": run.scenario, "elapsed_seconds": seconds, "row_type": "bin_and_event" if binned and seconds in event_times else "bin" if binned else "event", "cumulative_actions": action_cursor, "cumulative_requests": sum(counts.values()) if http else None, "cumulative_in_scope_requests": counts["in_scope"] if http else None, "cumulative_out_of_scope_requests": counts["out_of_scope"] if http else None, "cumulative_unknown_scope_requests": counts["unknown"] if http else None, "boundary_violation_observed": first_boundary is not None and first_boundary <= seconds, "impact_observed": impact is not None and impact <= seconds, "request_coverage": coverage, "series_unit": "observed_http_response_lower_bound" if http else "http_unmeasured_in_time", "timing_precision": "tool_completion_batch_or_service_event", "cumulative_port_scan_actions": scan_count, "cumulative_host_discovery_actions": host_count, "cumulative_tcp_connections": tcp_count if tcp else None})
        for unit in ("scan_address_targets", "reported_live_hosts"):
            values = [row for row in scanner if row["request_type"] == unit]
            rows[-1]["cumulative_" + unit] = sum(row["request_count"] for row in values if row["elapsed_seconds"] <= seconds) if values else None
    for milestone in milestones:
        seconds = milestone["elapsed_seconds"]
        if seconds is not None and http and 0 <= seconds <= duration:
            milestone["cumulative_requests"] = sum(row["request_count"] for row in http if row["elapsed_seconds"] <= seconds)
    return rows
