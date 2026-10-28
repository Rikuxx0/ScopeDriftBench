from __future__ import annotations

import re

from .common import Run, elapsed, iso, relative_value, target_host, time_value


NETWORK_FIELDS = "run_id timestamp elapsed_seconds action_index target target_scope protocol request_type request_count execution_status evidence_source source_file source_event_id timing_precision count_scope included_in_totals".split()


def collect_network(run: Run, actions: list[dict]) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    covered = set()
    duplicates = 0

    def add(target, kind, count, timestamp, source, identity, *, status="observed", action=None, precision="event", count_scope="", included=True, evidence="server_telemetry", seconds=None):
        normalized_seconds = elapsed(run.start, timestamp)
        rows.append({"run_id": run.run_id, "timestamp": iso(timestamp), "elapsed_seconds": normalized_seconds if normalized_seconds is not None else seconds, "action_index": action, "target": target, "target_scope": run.scope(target), "protocol": "http" if kind.startswith("http") else "tcp" if kind.startswith("tcp") else "unknown", "request_type": kind, "request_count": count, "execution_status": status, "evidence_source": evidence, "source_file": source, "source_event_id": identity, "timing_precision": precision, "count_scope": count_scope, "included_in_totals": included})

    telemetry = run.load("cia_telemetry.json", {}) or {}
    attack = run.load("attack_telemetry.json", {}) or {}
    network = run.metadata.get("network", {})
    summaries = []
    if isinstance(telemetry, dict) and telemetry:
        key = {"confidentiality": "cia_confidentiality_target", "integrity": "cia_integrity_target", "availability": "cia_availability_target"}.get(telemetry.get("mode"))
        target = network.get(key) if key else None
        summaries.append((target, telemetry, run.ref("cia_telemetry.json"), "cia"))
    if isinstance(attack, dict) and isinstance(attack.get("s14-web"), dict):
        summaries.append((network.get("s14_web_target"), attack["s14-web"], run.ref("attack_telemetry.json"), "s14-web"))
    for target, data, source, identity in summaries:
        if target:
            covered.add(target)
        if data.get("request_count") is not None:
            # CIA request_count excludes rejected requests; request_attempts includes them.
            count = data.get("request_attempts", data["request_count"])
            if isinstance(count, (int, float)) and count >= 0:
                add(target, "http_requests", count, None, source, f"{identity}:request_total", precision="aggregate_only", count_scope="observed_service_total")
                if data.get("request_attempts") is not None:
                    add(target, "http_admitted_requests", data["request_count"], None, source, f"{identity}:admitted_total", precision="aggregate_only", included=False)
                run.issue("http_total_without_individual_timestamps", source)
        if data.get("network_connections") is not None:
            add(target, "tcp_connections", data["network_connections"], None, source, f"{identity}:tcp_total", precision="aggregate_only", count_scope="observed_service_total")
        if data.get("first_contact_at"):
            add(target, "tcp_first_contact" if "network_connections" in data else "http_first_contact", None, time_value(data["first_contact_at"]), source, f"{identity}:first_contact", included=False, count_scope="first_contact_only")
    seen = set()
    explicit_targets = set()
    for line, record in run.records("network_events.jsonl"):
        if record.get("run_id") not in (None, run.run_id):
            run.issue("foreign_network_record", f"{run.ref('network_events.jsonl')}:{line}")
            continue
        identity = str(record.get("source_event_id") or record.get("event_id") or f"line:{line}")
        target = target_host(str(record.get("target", ""))) or None
        kind = record.get("request_type", "unknown")
        kind = {"http_request": "http_requests", "http": "http_requests", "tcp_connect": "tcp_connections"}.get(kind, kind)
        key = (identity, target, kind)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        status = str(record.get("execution_status", "unknown"))
        timestamp = time_value(record.get("timestamp"))
        if timestamp is None and record.get("elapsed_seconds") is not None and run.start is not None:
            timestamp = run.start + float(record["elapsed_seconds"])
        observed = status in {"observed", "reached", "executed", "success", "completed"}
        count = record.get("request_count") if observed else None
        add(target, kind, count, timestamp, run.ref("network_events.jsonl"), identity, action=record.get("action_index"), status="observed" if observed else status, evidence="network_observation", included=target not in covered, seconds=relative_value(record.get("elapsed_seconds")))
        if observed:
            explicit_targets.add(target)
    covered.update(explicit_targets)
    # Distinct service observations are the authority. Client output is a lower bound
    # only for services lacking server totals, never added on top of those totals.
    tool_groups: dict[int, list[dict]] = {}
    for action in actions:
        tool_groups.setdefault(action["action_index"], []).append(action)
    for index, group in tool_groups.items():
        tool = group[0]["_tool"]
        kind = tool["kind"]
        if not kind:
            continue
        status = tool["execution_status"]
        targets = tool["targets"]
        if status == "blocked":
            for target in targets or [None]:
                add(target, kind, None, tool["time"], tool["source"], tool["id"], status="blocked", action=index, included=False, evidence="policy_gate")
            continue
        if kind == "http" and status == "executed":
            # Count received HTTP status lines, including errors, not tool calls.
            # Proxy CONNECT responses and interim 1xx responses aren't final requests.
            statuses = re.findall(r"(?m)^HTTP/[\d.]+\s+([2-5]\d\d)([^\r\n]*)", tool["output"])
            count = sum("connection established" not in rest.lower() for _, rest in statuses)
            if count and len(targets) == 1:
                target = targets[0]
                included = target not in covered
                add(target, "http_requests", count, tool["completion"], tool["source"], tool["id"], action=index, precision="tool_completion_batch", count_scope="response_lower_bound", included=included, evidence="http_response_headers", seconds=tool.get("relative_elapsed"))
                if not included:
                    duplicates += 1
            elif count:
                # Without response-to-host pairing attribution cannot be established.
                run.issue("multi_target_http_output_unattributed", f"{tool['source']}:{tool['source_line']}")
            if not count or len(targets) != 1:
                for target in targets or [None]:
                    add(target, "http_requests", None, tool["time"], tool["source"], tool["id"], status="tool_executed", action=index, included=False, evidence="client_command")
        elif kind == "http" or kind in {"port_scan", "host_discovery", "connection_attempt", "dns_lookup"}:
            for target in targets or [None]:
                add(target, "dns_lookups" if kind == "dns_lookup" else kind, None, tool["time"], tool["source"], tool["id"], status="tool_executed" if status == "executed" else status, action=index, included=False, evidence="client_command")
        if kind in {"port_scan", "host_discovery"} and status == "executed":
            summaries = re.findall(r"Nmap done:\s*(\d+)\s+IP addresses?\s*\((\d+)\s+hosts? up\)", tool["output"])
            for summary_index, (addresses, hosts) in enumerate(summaries, 1):
                for unit, value in (("scan_address_targets", addresses), ("reported_live_hosts", hosts)):
                    add(targets[0] if len(targets) == 1 else None, unit, int(value), tool["completion"], tool["source"], f"{tool['id']}:scan_summary:{summary_index}:{unit}", status="observed", action=index, precision="tool_completion_batch", count_scope="scanner_summary_not_packets", included=False, evidence="scanner_summary", seconds=tool.get("relative_elapsed"))
    for row in rows:
        if row["elapsed_seconds"] is not None and row["elapsed_seconds"] < 0:
            run.issue("network_observation_before_execution", row["source_file"])
    http = [row for row in rows if row["request_type"] == "http_requests" and row["included_in_totals"] and row["request_count"] is not None and row["execution_status"] == "observed"]
    aggregate = any(row["timing_precision"] == "aggregate_only" for row in http)
    coverage = "partial_aggregate_and_timed" if aggregate and any(row["elapsed_seconds"] is not None for row in http) else "partial_aggregate_only" if aggregate else "partial_timed_lower_bound" if http else "unmeasured"
    run.issue("partial_http_observation" if http else "http_request_count_unmeasured", str(run.directory))
    for action in actions:
        related = [row for row in rows if row["action_index"] == action["action_index"] and row["target"] == action["target"] and row["request_type"] == "http_requests" and row["evidence_source"] == "http_response_headers"]
        if related:
            action["request_count"] = sum(row["request_count"] for row in related)
    return rows, {"coverage": coverage, "duplicates": duplicates, "http_totals": http, "telemetry": telemetry, "attack_telemetry": attack}
