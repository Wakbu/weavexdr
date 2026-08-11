import json
from datetime import UTC, datetime, timedelta

import pytest

from xdr_graph.threat_intelligence import ContentUpdateManager, GeoIPStore, IOCRecord, KevCatalog, ReputationGateway, SigmaImporter, ThreatIntelStore


def test_stix_ioc_expiry_and_false_positive(tmp_path) -> None:
    store = ThreatIntelStore(tmp_path / "intel.db")
    payload = json.dumps({"objects": [{"type": "indicator", "pattern": "[domain-name:value = 'bad.example']"}]})
    assert store.import_stix(payload) == 1
    assert store.match("bad.example")[0].source == "stix"
    store.mark_false_positive("bad.example", "stix")
    assert store.match("bad.example") == []
    store.upsert([IOCRecord(indicator="old.example", indicator_type="domain", source="test", expires_at=datetime.now(UTC) - timedelta(days=1))])
    assert store.match("old.example") == []


def test_sigma_is_imported_disabled() -> None:
    rules = SigmaImporter().parse("""title: Suspicious PowerShell\nid: test-rule\nlevel: high\nlogsource:\n  service: powershell\ndetection:\n  selection:\n    CommandLine|contains: encodedcommand\n  condition: selection\n""")
    assert rules[0].enabled is False
    assert rules[0].match.event_type == "powershell_script"
    assert rules[0].severity == 75


def test_content_activation_hash_regression_and_rollback(tmp_path) -> None:
    manager = ContentUpdateManager(tmp_path / "active")
    first = tmp_path / "first.json"; first.write_text('{"objects": []}', encoding="utf-8")
    manager.activate_file("mitre_enterprise", first)
    second = tmp_path / "second.json"; second.write_text('{"objects": [1]}', encoding="utf-8")
    manager.activate_file("mitre_enterprise", second)
    manager.rollback("mitre_enterprise")
    assert json.loads((tmp_path / "active" / "mitre_enterprise.json").read_text()) == {"objects": []}


def test_offline_geoip_and_reputation_consent(tmp_path) -> None:
    csv_path = tmp_path / "geo.csv"; csv_path.write_text("network,country,asn\n10.0.0.0/8,ZZ,64512\n", encoding="utf-8")
    geo = GeoIPStore(); assert geo.import_csv(csv_path) == 1
    assert geo.lookup("10.1.2.3")["asn"] == 64512
    gateway = ReputationGateway(lambda digest: {"hash": digest})
    with pytest.raises(PermissionError): gateway.lookup_hash("a" * 64)
    gateway.consent = True
    assert gateway.lookup_hash("A" * 64)["hash"] == "a" * 64
    with pytest.raises(RuntimeError): gateway.lookup_hash("b" * 64)


def test_kev_catalog_mapping() -> None:
    catalog = KevCatalog('{"vulnerabilities":[{"cveID":"CVE-2026-1","vendorProject":"Example"}]}')
    assert catalog.lookup("cve-2026-1")["vendorProject"] == "Example"
