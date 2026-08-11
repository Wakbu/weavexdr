import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_operational_matrix_writes_bounded_evidence(tmp_path):
    output = tmp_path / "matrix.json"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "run_operational_matrix.py"), "--duration-seconds", "1", "--sample-seconds", ".1", "--output", str(output)], check=True, timeout=10)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "completed"
    assert payload["samples"]
    assert payload["peak_bytes"] >= payload["final_bytes"]


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
