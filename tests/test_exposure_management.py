from datetime import UTC, datetime, timedelta

from xdr_graph.exposure_management import build_exposure_overview
from xdr_graph.models import IncidentReport


def test_exposure_overview_prioritizes_observed_surface_and_keeps_cve_unknown():
    timestamp = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    report = IncidentReport.model_validate({
        "incident_id": "exposure-1", "verdict": "suspicious", "risk_score": 82,
        "evidence": [], "recommended_actions": [],
        "validation": {"passed": True, "errors": [], "review_count": 0},
        "source_events": [
            {"event_id": "r1", "event_type": "remote_access", "timestamp": timestamp,
             "windows_event_id": 4624, "channel": "Security", "action": "rdp login",
             "user": "local-admin", "source_ip": "8.8.8.8"},
            {"event_id": "p1", "event_type": "scheduled_task", "timestamp": timestamp,
             "windows_event_id": 4698, "channel": "Security", "action": "task created",
             "user": "local-admin"},
        ],
    })
    result = build_exposure_overview(
        [report], collector_status={"state": "running"}, integrity_state="healthy",
        startup_active=True,
        software=[{"name": "Unknown Utility", "version": "1.0", "publisher": "게시자 미확인"}],
    )

    assert result["privacy"] == "local_only"
    assert result["vulnerability_feed"] == "not_configured"
    assert result["signals"]["remote_access"] == 1
    assert result["signals"]["persistence"] == 1
    assert result["signals"]["external_ips"] == [("8.8.8.8", 1)]
    identifiers = {item["id"] for item in result["recommendations"]}
    assert {"remote-surface", "persistence-surface", "software-metadata"} <= identifiers
    assert result["secure_score"] < 100


def test_exposure_overview_penalizes_missing_core_protection():
    result = build_exposure_overview(
        [], collector_status={"state": "not_configured"}, integrity_state="tamper_detected",
        startup_active=False, software=[],
    )
    identifiers = {item["id"] for item in result["recommendations"]}
    assert {"collector-gap", "integrity-gap", "startup-gap", "telemetry-gap"} <= identifiers
    assert result["secure_score"] <= 25
