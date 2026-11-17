"""Strict, dependency-free research archive writer and streaming verifier."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

VERSION = 1
TOOL_VERSION = "1"
ALLOWED = {"metadata.json", "agent_prompt.txt", "policy.yaml", "scenario.yaml", "events.jsonl",
           "metrics.json", "violations.json", "agent_output.txt", "cia_summary.json",
           "cia_telemetry.json", "cia_ground_truth.yaml", "attack_telemetry.json",
           "attack_ground_truth.yaml", "codex_trace.jsonl", "pentestcode_trace.jsonl", "local_trace.jsonl"}
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
SENSITIVE = {"token": re.compile(rb'(?i)(?:bearer\s+|["\']token["\']\s*[:=]|sk-[A-Za-z0-9]{12})'),
             "cookie": re.compile(rb'(?i)(?:set-cookie:|cookie:)'),
             "password": re.compile(rb'(?i)["\']password["\']\s*[:=]')}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def valid_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not name.startswith("/") and "\\" not in name and all(p not in {"", ".", ".."} for p in name.split("/")) and str(path) == name


def _run_dir(results: Path, run_id: str) -> Path:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid run ID")
    path = results / run_id
    if path.is_symlink() or not path.is_dir() or not (path / "metadata.json").is_file():
        raise ValueError(f"Run directory unavailable: {run_id}")
    return path


def sensitive_indicators(source: Path) -> list[str]:
    found = set()
    for path in source.iterdir():
        if path.name not in ALLOWED or path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                for label, pattern in SENSITIVE.items():
                    if pattern.search(chunk):
                        found.add(label)
    return sorted(found)


def export_run(results: Path, run_id: str, output: Path, repo: Path) -> Path:
    source = _run_dir(results, run_id)
    metadata = json.loads((source / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("run_id") != run_id or metadata.get("status") not in {"evaluated", "execution_failed", "interrupted"}:
        raise ValueError("Run is active, incomplete, or has inconsistent metadata")
    marker = results / ".active_run"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() == run_id:
        raise ValueError("Active run cannot be exported")
    files = []
    for path in sorted(source.iterdir()):
        if path.name not in ALLOWED:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Unsafe result entry: {path.name}")
        if path.stat().st_size > MAX_FILE:
            raise ValueError(f"Result file exceeds size limit: {path.name}")
        files.append(path)
    if not files:
        raise ValueError("No exportable files")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=False)
    manifest = {"format_version": VERSION, "export_tool_version": TOOL_VERSION,
                "created_at_utc": datetime.now(timezone.utc).isoformat(), "run_id": run_id,
                "repository_commit_sha": commit.stdout.strip() if commit.returncode == 0 else None,
                "evaluation_status": metadata.get("status"), "model": metadata.get("model_id"),
                "provider": metadata.get("provider"), "harness": metadata.get("harness"), "files": []}
    for path in files:
        raw = path.read_bytes()
        manifest["files"].append({"path": f"runs/{run_id}/{path.name}", "size": len(raw), "sha256": digest(raw)})
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"experiment-{run_id}.tar.gz"
    if archive.exists() or Path(str(archive) + ".sha256").exists():
        raise FileExistsError("Export already exists; choose another output directory")
    temporary = output / f".{archive.name}.partial"
    try:
        with tarfile.open(temporary, "w:gz") as tar:
            for path in files:
                raw = path.read_bytes()
                expected = next(item for item in manifest["files"] if item["path"].endswith("/" + path.name))
                if len(raw) != expected["size"] or digest(raw) != expected["sha256"]:
                    raise RuntimeError("Source changed during export")
                info = tarfile.TarInfo(expected["path"])
                info.size, info.mode = len(raw), 0o600
                tar.addfile(info, io.BytesIO(raw))
            raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mode = len(raw), 0o600
            tar.addfile(info, io.BytesIO(raw))
        temporary.replace(archive)
        Path(str(archive) + ".sha256").write_text(f"{file_digest(archive)}  {archive.name}\n", encoding="ascii")
    finally:
        temporary.unlink(missing_ok=True)
    return archive


def verify_archive(archive: Path) -> dict:
    issues = []
    if archive.is_symlink() or not archive.is_file():
        return {"status": "FAIL", "run_id": None, "issues": ["Archive is missing or a symlink"], "files_checked": 0}
    checksum = Path(str(archive) + ".sha256")
    if checksum.is_symlink() or not checksum.is_file():
        issues.append("Missing external checksum")
    else:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)\n?", checksum.read_text(encoding="ascii"))
        if not match or match.group(2) != archive.name or match.group(1) != file_digest(archive):
            issues.append("Archive SHA-256 mismatch")
    seen: set[str] = set()
    observed: dict[str, tuple[int, str]] = {}
    manifest = None
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                name = member.name
                if not valid_name(name) or name in seen or not member.isfile() or member.size > MAX_FILE:
                    issues.append(f"Unsafe or duplicate member: {name}")
                    continue
                seen.add(name)
                if name != "manifest.json" and not re.fullmatch(r"runs/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[^/]+", name):
                    issues.append(f"Unexpected member: {name}")
                    continue
                if name == "manifest.json" and member.size > MAX_MANIFEST:
                    issues.append("Manifest too large")
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    issues.append(f"Unreadable member: {name}")
                    continue
                if name == "manifest.json":
                    manifest = json.loads(stream.read())
                else:
                    sha = hashlib.sha256()
                    size = 0
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        sha.update(chunk)
                        size += len(chunk)
                    observed[name] = (size, sha.hexdigest())
    except (OSError, EOFError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
        issues.append(f"Unreadable archive: {type(exc).__name__}")
    run_id = manifest.get("run_id") if isinstance(manifest, dict) else None
    if not isinstance(manifest, dict) or manifest.get("format_version") != VERSION or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id) or not isinstance(manifest.get("files"), list):
        issues.append("Invalid manifest")
    else:
        if archive.name != f"experiment-{run_id}.tar.gz":
            issues.append("Archive name and run ID differ")
        expected = {}
        for row in manifest["files"]:
            if not isinstance(row, dict):
                issues.append("Invalid file entry")
                continue
            name = row.get("path")
            if not isinstance(name, str) or not valid_name(name) or not name.startswith(f"runs/{run_id}/") or name.split("/")[-1] not in ALLOWED or name in expected or not isinstance(row.get("size"), int) or row["size"] < 0 or not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
                issues.append(f"Invalid file entry: {name}")
                continue
            expected[name] = (row["size"], row["sha256"])
        if set(expected) != set(observed):
            issues.append("Missing or unexpected files")
        for name in expected.keys() & observed.keys():
            if expected[name] != observed[name]:
                issues.append(f"Size or SHA-256 mismatch: {name}")
        if seen != set(expected) | {"manifest.json"}:
            issues.append("Unexpected archive members")
    return {"status": "PASS" if not issues else "FAIL", "run_id": run_id, "issues": issues, "files_checked": len(observed)}
