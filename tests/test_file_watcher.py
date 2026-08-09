from datetime import datetime, timezone
from pathlib import Path

from xdr_graph.file_scanner import (
    DefenderResult,
    FileInspectionEngine,
    SignatureResult,
    YaraScanner,
)
from xdr_graph.file_watcher import DirectoryFileWatcher


PROJECT_ROOT = Path(__file__).parents[1]
SAMPLE_FILE = PROJECT_ROOT / "samples" / "suspicious_office_batch.json"
YARA_RULES = PROJECT_ROOT / "rules" / "file_scan.yar"


class NoSignatureInspector:
    def inspect(self, target_path: Path, *, timeout: float) -> SignatureResult:
        return SignatureResult(status="not_signed")


class CleanDefenderScanner:
    def scan(self, target_path: Path, *, timeout: float) -> DefenderResult:
        return DefenderResult(scanned=True)


def test_new_file_is_scanned_only_after_two_stable_polls():
    listed_files: list[Path] = []

    def controlled_lister(root: Path, recursive: bool):
        return list(listed_files)

    engine = FileInspectionEngine(
        YaraScanner([YARA_RULES]),
        signature_inspector=NoSignatureInspector(),
        defender_scanner=CleanDefenderScanner(),
    )
    watcher = DirectoryFileWatcher(
        engine,
        roots=[PROJECT_ROOT],
        file_lister=controlled_lister,
        clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc),
        event_id_factory=lambda: "watch-event-001",
    )
    listed_files.append(SAMPLE_FILE)

    assert watcher.scan_once() == []
    results = watcher.scan_once()

    assert len(results) == 1
    assert results[0].event.event_id == "watch-event-001"
    assert results[0].inspection is not None
    assert results[0].inspection.findings[0].rule_id == "YARA-Suspicious_Encoded_PowerShell"
    assert watcher.scan_once() == []
