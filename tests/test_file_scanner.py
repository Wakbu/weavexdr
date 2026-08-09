import hashlib
import json
from pathlib import Path

from xdr_graph.file_scanner import (
    AuthenticodeInspector,
    DefenderResult,
    DefenderScanner,
    FileInspectionEngine,
    SignatureResult,
    YaraScanner,
)


PROJECT_ROOT = Path(__file__).parents[1]
SAMPLE_FILE = PROJECT_ROOT / "samples" / "suspicious_office_batch.json"
YARA_RULES = PROJECT_ROOT / "rules" / "file_scan.yar"


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
        def inspect(self, target_path: Path) -> SignatureResult:
            return SignatureResult(status="invalid")

    class FixedDefenderScanner:
        def scan(self, target_path: Path) -> DefenderResult:
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
