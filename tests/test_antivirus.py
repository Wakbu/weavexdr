import hashlib
import os
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from xdr_graph.antivirus import AdvancedFileScanner, ArchiveAnalyzer, InspectionCache, ScanJobManager, ScanPolicy
from xdr_graph.file_scanner import DefenderResult, FileInspectionResult, FileMetadata, SignatureResult


class FakeEngine:
    def __init__(self) -> None:
        self.calls = 0

    def inspect(self, file_path: str | Path, *, event_id: str) -> FileInspectionResult:
        self.calls += 1
        path = Path(file_path)
        data = path.read_bytes()
        return FileInspectionResult(
            metadata=FileMetadata(path=str(path), size_bytes=len(data), modified_at=datetime.now(UTC), mime_type=None, sha256=hashlib.sha256(data).hexdigest()),
            signature=SignatureResult(status="valid", signer="Trusted Publisher"),
            yara_matches=(), defender=DefenderResult(scanned=True), findings=(), errors=(),
        )


def test_cache_invalidates_and_signer_exclusion(tmp_path) -> None:
    target = tmp_path / "sample.bin"; target.write_bytes(b"first")
    engine = FakeEngine()
    scanner = AdvancedFileScanner(engine, cache=InspectionCache(tmp_path / "cache.db"), policy=ScanPolicy(excluded_signers=["trusted"]))
    assert scanner.inspect(target, event_id="one").excluded_reason == "excluded signer"
    assert scanner.inspect(target, event_id="two").cached is True
    target.write_bytes(b"second")
    assert scanner.inspect(target, event_id="three").cached is False
    assert engine.calls == 2


def test_archive_bomb_policy_and_scan_job_progress(tmp_path) -> None:
    archive_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", "A" * 50_000)
    result = ArchiveAnalyzer().analyze(archive_path, ScanPolicy(archive_max_ratio=2))
    assert result and result["blocked"] is True
    target = tmp_path / "file.txt"; target.write_text("safe", encoding="utf-8")
    manager = ScanJobManager(AdvancedFileScanner(FakeEngine(), cache=InspectionCache(tmp_path / "jobs.db")))
    job = manager.start([str(target)], profile="custom")
    for _ in range(100):
        job = manager.get(job.job_id)
        if job.state in {"completed", "failed"}: break
        time.sleep(0.01)
    assert job.state == "completed"
    assert job.scanned_files == job.total_files == 1
    manager.close()


def test_quick_scan_filters_old_or_low_risk_files(tmp_path) -> None:
    recent_executable = tmp_path / "download.exe"
    recent_executable.write_bytes(b"MZ" + b"safe" * 20)
    recent_text = tmp_path / "notes.txt"
    recent_text.write_text("plain text", encoding="utf-8")
    old_script = tmp_path / "old.ps1"
    old_script.write_text("Write-Host safe", encoding="utf-8")
    old_time = time.time() - 31 * 86400
    os.utime(old_script, (old_time, old_time))

    files = ScanJobManager._expand([str(tmp_path)], "quick")

    assert files == [recent_executable]


def test_scan_job_parallelizes_static_file_inspection(tmp_path) -> None:
    class SlowEngine(FakeEngine):
        def inspect(self, file_path: str | Path, *, event_id: str) -> FileInspectionResult:
            time.sleep(.08)
            return super().inspect(file_path, event_id=event_id)

    for index in range(12):
        (tmp_path / f"sample-{index}.bin").write_bytes(b"safe")
    manager = ScanJobManager(
        AdvancedFileScanner(SlowEngine(), cache=InspectionCache(tmp_path.parent / f"{tmp_path.name}-parallel.db")),
        file_workers=4,
    )
    started = time.monotonic()
    job = manager.start([str(tmp_path)], profile="custom")
    for _ in range(200):
        job = manager.get(job.job_id)
        if job.state in {"completed", "failed"}:
            break
        time.sleep(.01)
    elapsed = time.monotonic() - started

    assert job.state == "completed"
    assert job.scanned_files == 12
    assert job.files_per_second > 10
    assert elapsed < .7
    manager.close()


def test_scan_job_reports_inaccessible_requested_path(tmp_path) -> None:
    manager = ScanJobManager(AdvancedFileScanner(FakeEngine()))
    job = manager.start([str(tmp_path / "missing")], profile="custom")
    for _ in range(100):
        job = manager.get(job.job_id)
        if job.state == "failed":
            break
        time.sleep(.01)
    assert job.state == "failed"
    assert "accessible" in (job.error or "")
    manager.close()
