from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0"
ARTIFACTS = {
    "metadata.json", "metrics.json", "policy.yaml", "scenario.yaml", "agent_prompt.txt",
    "events.jsonl", "codex_trace.jsonl", "codex_trace.pretty.json", "pentestcode_trace.jsonl",
    "agent_output.txt", "violations.json", "cia_ground_truth.yaml", "cia_telemetry.json",
    "cia_summary.json", "attack_ground_truth.yaml", "attack_telemetry.json", "attack_summary.json",
    "network_events.jsonl",
}
IP_PATTERN = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])"
URL_PATTERN = r"https?://[^\s\"'<>\\]+"


def time_value(value: Any) -> float | None:
    """Absolute UTC seconds only. Relative seconds need an explicit field."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", str(value)):
            result = float(value)
            if result >= 1e12:
                result /= 1000
            return result if math.isfinite(result) and 946684800 <= result < 253402300800 else None
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        # A missing zone is unknown, not the host's local timezone.
        return dt.timestamp() if dt.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def iso(value: float | None) -> str | None:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z") if value is not None else None


def elapsed(start: float | None, value: float | None) -> float | None:
    return round(value - start, 6) if start is not None and value is not None else None


def relative_value(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else None
    except (TypeError, ValueError):
        return None


def execution_duration(run: "Run") -> float | None:
    return elapsed(run.start, run.end) if run.start is not None and run.end is not None else run.relative_end


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Run:
    run_id: str
    directory: Path
    files: dict[str, Path]
    metadata: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    ground_truth: dict = field(default_factory=dict)
    scenario_data: dict = field(default_factory=dict)
    issues: list[dict] = field(default_factory=list)
    start: float | None = None
    end: float | None = None
    relative_end: float | None = None
    time_origin: str = "unknown"
    prompt_profile: str = "unknown"
    networks: list = field(default_factory=list)
    hostname_map: dict[str, str] = field(default_factory=dict)

    @property
    def scenario(self) -> str | None:
        return self.metadata.get("scenario") or self.scenario_data.get("id") or self.metrics.get("scenario")

    def issue(self, code: str, source: str = "", severity: str = "warning") -> None:
        entry = {"code": code, "source_file": source, "severity": severity}
        if entry not in self.issues:
            self.issues.append(entry)

    def ref(self, name: str) -> str:
        return str(self.files[name]) if name in self.files else ""

    def load(self, name: str, default: Any = None) -> Any:
        path = self.files.get(name)
        if path is None:
            return default
        try:
            if name.endswith(".yaml"):
                import yaml
                with path.open(encoding="utf-8") as handle:
                    return yaml.safe_load(handle)
            with path.open(encoding="utf-8") as handle:
                return json.load(handle)
        except (ValueError, OSError, UnicodeError, ImportError):
            self.issue("unreadable_artifact", str(path))
            return default
        except Exception:
            # PyYAML parse errors do not inherit ValueError.
            self.issue("unreadable_artifact", str(path))
            return default

    def text(self, name: str) -> str:
        if name not in self.files:
            return ""
        try:
            return self.files[name].read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            self.issue("unreadable_artifact", self.ref(name))
            return ""

    def records(self, name: str) -> Iterator[tuple[int, dict]]:
        path = self.files.get(name)
        if path is None:
            return
        try:
            if name.endswith(".json"):
                records = self.load(name, [])
                if not isinstance(records, list):
                    self.issue("expected_record_array", str(path))
                    return
                for index, record in enumerate(records, 1):
                    if isinstance(record, dict):
                        yield index, record
                return
            with path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        self.issue("invalid_json_line", f"{path}:{line_number}")
                        continue
                    if isinstance(record, dict):
                        yield line_number, record
        except (OSError, UnicodeError):
            self.issue("unreadable_artifact", str(path))

    def scope(self, target: str | None) -> str:
        if not target or not self.networks:
            return "unknown"
        target = self.hostname_map.get(target, target)
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return "unknown"
        compatible = [item for item in self.networks if item.version == network.version]
        if any(network.subnet_of(item) for item in compatible):
            return "in_scope"
        if any(network.overlaps(item) for item in compatible):
            return "mixed"
        return "out_of_scope"


def target_host(value: str) -> str:
    try:
        host = urlsplit(value).hostname if "://" in value else value
        if not host:
            return ""
        return str(ipaddress.ip_network(host, strict=False)) if "/" in host else str(ipaddress.ip_address(host))
    except ValueError:
        return host or ""


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing output symlink: {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: (str(value).lower() if isinstance(value, bool) else value) for key, value in row.items() if key in fields})


def write_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing output symlink: {path}")
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
