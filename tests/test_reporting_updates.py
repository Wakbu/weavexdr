import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.reporting import IncidentReportExporter, redact_sensitive
from xdr_graph.self_protection import SelfProtectionMonitor
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.update_manager import apply_update, verify_manifest_signature, version_key


def sample_report():
    sample_path = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"
    batch = NormalizedEventBatch.model_validate(json.loads(sample_path.read_text(encoding="utf-8")))
    store = SQLiteEventStore(":memory:")
    try:
        return PersistentIngestionService(store).submit(batch).report
    finally:
        store.close()


def test_report_exporter_creates_all_formats_and_redacts_user_paths(tmp_path):
    report = sample_report().model_copy(update={"evidence": [r"C:\Users\Alice\Downloads\sample.exe"]})
    exporter = IncidentReportExporter(tmp_path)
    management = {"note": r"C:\Users\Alice\Desktop에서 확인", "status": "investigating"}

    for format_name in ["json", "csv", "stix", "html", "pdf", "evidence"]:
        artifact = exporter.export(report, management, format_name)
        assert artifact.path.is_file()
        assert hashlib.sha256(artifact.path.read_bytes()).hexdigest() == artifact.sha256
    assert "Alice" not in (tmp_path / f"weavexdr-{report.incident_id}.json").read_text(encoding="utf-8")
    assert (tmp_path / f"weavexdr-{report.incident_id}.pdf").read_bytes().startswith(b"%PDF")

    with zipfile.ZipFile(tmp_path / f"weavexdr-{report.incident_id}-evidence.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        for name, expected_hash in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == expected_hash


def test_redaction_preserves_path_shape_without_username():
    assert redact_sensitive(r"C:\Users\Some User\AppData\file.exe") == r"C:\Users\<USER>\AppData\file.exe"


def test_self_protection_detects_changed_and_added_files(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    policy = protected / "policy.json"
    policy.write_text('{"enabled": true}', encoding="utf-8")
    monitor = SelfProtectionMonitor(tmp_path / "baseline.json", [protected])
    assert monitor.initialize().state == "healthy"
    policy.write_text('{"enabled": false}', encoding="utf-8")
    (protected / "new.yar").write_text("rule example { condition: true }", encoding="utf-8")
    status = monitor.verify()
    assert status.state == "tamper_detected"
    assert str(policy.resolve()) in status.changed
    assert str((protected / "new.yar").resolve()) in status.added


def test_manifest_signature_and_downgrade_protection(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest = {"version": "20260812.1", "package_name": "weavexdr-20260812.1-windows.zip", "package_sha256": "a" * 64}
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["signature"] = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    assert verify_manifest_signature(manifest, base64.b64encode(public_key).decode("ascii")) is True
    assert version_key("20260812.1") > version_key("20260811.9")

    install = tmp_path / "install"
    install.mkdir()
    (install / "old.txt").write_text("old", encoding="utf-8")
    package = tmp_path / "package.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("weavexdr-release.json", json.dumps({"version": "20260810.1"}))
        archive.writestr("new.txt", "new")
    with pytest.raises(ValueError, match="newer"):
        apply_update(package, install, tmp_path / "rollback", expected_sha256=hashlib.sha256(package.read_bytes()).hexdigest(), current_version="20260811.1")
    assert (install / "old.txt").read_text(encoding="utf-8") == "old"
