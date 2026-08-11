import hashlib
import json
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest
import yara

from xdr_graph.file_scanner import (
    AuthenticodeInspector,
    DefenderResult,
    DefenderScanner,
    FileInspectionEngine,
    FileTooLargeError,
    SignatureResult,
    YaraScanner,
    _run_powershell_json,
)


PROJECT_ROOT = Path(__file__).parents[1]
SAMPLE_FILE = PROJECT_ROOT / "samples" / "suspicious_office_batch.json"
BENIGN_FILE = PROJECT_ROOT / "samples" / "benign_document.txt"
YARA_RULES = PROJECT_ROOT / "rules" / "file_scan.yar"


def test_powershell_scanners_do_not_open_a_console_window(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _run_powershell_json("Write-Output '{}'", SAMPLE_FILE, 1) == "{}"
    assert captured["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)


def test_yara_scanner_matches_the_encoded_powershell_sample():
    matches = YaraScanner([YARA_RULES]).scan(SAMPLE_FILE)

    assert [match.rule for match in matches] == ["Suspicious_Encoded_PowerShell"]
    assert matches[0].severity == 70


def test_authenticode_output_is_normalized_without_using_a_real_certificate():
    def fake_runner(script: str, target: Path, timeout: float) -> str:
        return json.dumps(
            {
                "Status": "Valid",
                "StatusMessage": "Signature verified",
                "Signer": "CN=Example Publisher",
                "TimestampSigner": "CN=Example Timestamp",
            }
        )

    result = AuthenticodeInspector(fake_runner).inspect(SAMPLE_FILE)

    assert result.status == "valid"
    assert result.signer == "CN=Example Publisher"


def test_defender_detection_is_normalized():
    def fake_runner(script: str, target: Path, timeout: float) -> str:
        return json.dumps({"ThreatNames": ["Test.Threat"]})

    result = DefenderScanner(fake_runner).scan(SAMPLE_FILE)

    assert result.scanned is True
    assert result.threat_names == ("Test.Threat",)


def test_file_inspection_collects_metadata_and_creates_findings():
    class FixedSignatureInspector:
        def inspect(self, target_path: Path, *, timeout: float) -> SignatureResult:
            return SignatureResult(status="invalid")

    class FixedDefenderScanner:
        def scan(self, target_path: Path, *, timeout: float) -> DefenderResult:
            return DefenderResult(scanned=True, threat_names=("Test.Threat",))

    engine = FileInspectionEngine(
        YaraScanner([YARA_RULES]),
        signature_inspector=FixedSignatureInspector(),
        defender_scanner=FixedDefenderScanner(),
    )
    result = engine.inspect(SAMPLE_FILE, event_id="event-file")

    expected_hash = hashlib.sha256(SAMPLE_FILE.read_bytes()).hexdigest()
    assert result.metadata.sha256 == expected_hash
    assert result.metadata.size_bytes == SAMPLE_FILE.stat().st_size
    assert {finding.rule_id for finding in result.findings} == {
        "YARA-Suspicious_Encoded_PowerShell",
        "DEFENDER-MALWARE",
        "SIGNATURE-INVALID",
    }


def test_safe_benign_and_inert_suspicious_files_are_distinguished():
    class NoSignatureInspector:
        def inspect(self, target_path: Path, *, timeout: float) -> SignatureResult:
            return SignatureResult(status="not_signed")

    class CleanDefenderScanner:
        def scan(self, target_path: Path, *, timeout: float) -> DefenderResult:
            return DefenderResult(scanned=True)

    engine = FileInspectionEngine(
        YaraScanner([YARA_RULES]),
        signature_inspector=NoSignatureInspector(),
        defender_scanner=CleanDefenderScanner(),
    )

    benign_result = engine.inspect(BENIGN_FILE, event_id="event-benign")
    suspicious_result = engine.inspect(SAMPLE_FILE, event_id="event-inert-suspicious")

    assert benign_result.findings == ()
    assert suspicious_result.findings[0].rule_id == "YARA-Suspicious_Encoded_PowerShell"


def test_file_size_limit_is_enforced_before_scanners_run():
    engine = FileInspectionEngine(
        YaraScanner([YARA_RULES]), max_file_size_bytes=10
    )

    with pytest.raises(FileTooLargeError, match="inspection limit"):
        engine.inspect(SAMPLE_FILE, event_id="event-too-large")


def test_scanner_failures_are_preserved_as_partial_result_errors():
    class ErrorSignatureInspector:
        def inspect(self, target_path: Path, *, timeout: float) -> SignatureResult:
            assert timeout == 3
            return SignatureResult(status="error", message="signature timeout")

    class ErrorYaraScanner:
        def scan(self, target_path: Path, *, timeout: int):
            assert timeout == 4
            raise yara.Error("rule failure")

    class ErrorDefenderScanner:
        def scan(self, target_path: Path, *, timeout: float) -> DefenderResult:
            assert timeout == 5
            return DefenderResult(scanned=False, error="Defender unavailable")

    engine = FileInspectionEngine(
        ErrorYaraScanner(),
        signature_inspector=ErrorSignatureInspector(),
        defender_scanner=ErrorDefenderScanner(),
        signature_timeout=3,
        yara_timeout=4,
        defender_timeout=5,
    )

    result = engine.inspect(BENIGN_FILE, event_id="event-partial")

    assert result.findings == ()
    assert result.errors == (
        "signature: signature timeout",
        "yara: rule failure",
        "defender: Defender unavailable",
    )


def test_batch_mode_skips_per_file_signature_and_defender_processes(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("safe", encoding="utf-8")

    class FailingSignature:
        def inspect(self, *_args, **_kwargs):
            raise AssertionError("signature process should not run")

    class FailingDefender:
        def scan(self, *_args, **_kwargs):
            raise AssertionError("Defender process should not run per file")

    class CleanYara:
        def scan(self, *_args, **_kwargs):
            return ()

    engine = FileInspectionEngine(
        CleanYara(), signature_inspector=FailingSignature(), defender_scanner=FailingDefender()
    )
    result = engine.inspect(
        target,
        event_id="batch-file",
        include_signature=False,
        include_defender=False,
    )

    assert result.signature.status == "unavailable"
    assert result.defender.scanned is True
