import io
import json
import tarfile

import pytest

from runner.offline_archive import export_run, verify_archive


def run(results, run_id="run-1", status="evaluated"):
    path = results / run_id
    path.mkdir()
    (path / "metadata.json").write_text(json.dumps({"run_id": run_id, "status": status, "model_id": "test"}))
    (path / "events.jsonl").write_text('{"type":"tool"}\n')
    return path


def test_export_verify_preserves_results(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    source = run(results)
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    archive = export_run(results, "run-1", tmp_path / "exports", tmp_path)
    assert verify_archive(archive)["status"] == "PASS"
    assert before == {p.name: p.read_bytes() for p in source.iterdir()}
    with archive.open("ab") as handle:
        handle.write(b"extra")
    assert verify_archive(archive)["status"] == "FAIL"


def test_active_and_symlink_rejected(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    source = run(results)
    (results / ".active_run").write_text("run-1\n")
    with pytest.raises(ValueError):
        export_run(results, "run-1", tmp_path / "exports", tmp_path)
    (results / ".active_run").unlink()
    (source / "policy.yaml").symlink_to(source / "metadata.json")
    with pytest.raises(ValueError):
        export_run(results, "run-1", tmp_path / "exports", tmp_path)


@pytest.mark.parametrize("bad_name", ["runs/run-1/../evil", "/absolute", "runs/run-1/metadata.json"])
def test_untrusted_archive_rejected(tmp_path, bad_name):
    archive = tmp_path / "experiment-run-1.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = b"evil"
        info = tarfile.TarInfo(bad_name)
        info.size = len(data)
        if bad_name.endswith("metadata.json"):
            info.type = tarfile.SYMTYPE
            info.linkname = "../../evil"
            tar.addfile(info)
        else:
            tar.addfile(info, io.BytesIO(data))
    assert verify_archive(archive)["status"] == "FAIL"


def test_missing_or_altered_member_rejected(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    run(results)
    archive = export_run(results, "run-1", tmp_path / "exports", tmp_path)
    with tarfile.open(archive) as tar:
        manifest = json.load(tar.extractfile("manifest.json"))
    manifest["files"][0]["sha256"] = "0" * 64
    altered = tmp_path / "experiment-run-1.tar.gz"
    with tarfile.open(altered, "w:gz") as tar:
        data = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    assert verify_archive(altered)["status"] == "FAIL"


def test_multiple_runs_export_independently_without_docker(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    run(results, "run-1")
    run(results, "run-2")
    archives = [export_run(results, item, tmp_path / "exports", tmp_path) for item in ("run-1", "run-2")]
    assert all(verify_archive(item)["status"] == "PASS" for item in archives)


def test_invalid_manifest_and_duplicate_member_rejected(tmp_path):
    archive = tmp_path / "experiment-run-1.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, data in (("manifest.json", b"{}"), ("manifest.json", b"{}")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    assert verify_archive(archive)["status"] == "FAIL"
