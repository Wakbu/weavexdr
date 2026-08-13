import json
import subprocess
import sys
from pathlib import Path

from scripts.validate_windows_matrix import validate_matrix

ROOT = Path(__file__).parents[1]


def test_operational_matrix_writes_bounded_evidence(tmp_path):
    output = tmp_path / "matrix.json"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "run_operational_matrix.py"), "--duration-seconds", "1", "--sample-seconds", ".1", "--output", str(output)], check=True, timeout=10)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "passed"
    assert payload["samples"]
    assert payload["peak_bytes"] >= payload["final_bytes"]
    assert payload["scenario"] == "baseline"
    assert all(sample["process_alive"] for sample in payload["samples"])
    assert "memory_growth_bytes_per_hour" in payload
    assert payload["growth_gate_applied"] is False


def test_supply_chain_report_contains_components_and_asset_hash(tmp_path):
    asset = tmp_path / "asset.zip"; asset.write_bytes(b"release")
    output = tmp_path / "sbom.json"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_supply_chain_report.py"), "--output", str(output), "--asset", str(asset)], check=True, timeout=20)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["components"]
    assert payload["properties"][0]["value"].startswith("asset.zip:")


def test_recovery_and_updater_scripts_keep_their_safety_boundaries():
    updater = (ROOT / "scripts" / "apply_update.ps1").read_text(encoding="utf-8")
    recovery = (ROOT / "scripts" / "recover_weavexdr_network.ps1").read_text(encoding="utf-8")
    assert "weavexdr-release.json" in updater and "ExpectedSha256" in updater and ".update-rollback" in updater
    assert "WeaveXDR-*" in recovery and "Remove-NetFirewallRule" in recovery


def test_windows_validation_wrapper_has_bounded_scenarios_and_output():
    wrapper = (ROOT / "scripts" / "run_windows_validation.ps1").read_text(encoding="utf-8")
    assert "ValidateSet('baseline','sleep-resume','user-switch','network-change','install-update-remove')" in wrapper
    assert "OutputRoot must stay inside the project" in wrapper
    assert "[int]$ProcessId = $PID" in wrapper
    assert "New-Item -ItemType Directory -Path" in wrapper


def test_windows_matrix_requires_both_operating_systems_and_long_runs(tmp_path):
    partial = {
        "status": "passed",
        "platform": "Windows-11-10.0.26200",
        "windows_edition": "Windows 11",
        "scenario": "baseline",
        "duration_seconds": 604800,
    }
    (tmp_path / "win11.json").write_text(json.dumps(partial), encoding="utf-8")
    report = validate_matrix(tmp_path)
    assert report["status"] == "incomplete"
    assert "windows-10:24h" in report["missing"]
    assert report["systems"]["windows-11"]["24h"] is True
    assert report["systems"]["windows-11"]["7d"] is True


def test_windows_trust_validator_requires_signature_timestamp_and_manual_reputation():
    validator = (ROOT / "scripts" / "validate_windows_trust.ps1").read_text(encoding="utf-8")
    assert "Get-AuthenticodeSignature" in validator
    assert "TimeStamperCertificate" in validator
    assert "manual-external-validation-required" in validator
    assert "if (-not $FilePath)" in validator


def test_executable_build_allows_the_documented_shutdown_watchdog():
    builder = (ROOT / "scripts" / "build_local_executable.ps1").read_text(encoding="utf-8")
    assert "WaitForExit(25000)" in builder
