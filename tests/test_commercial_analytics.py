from datetime import UTC, datetime, timedelta

import pytest

from xdr_graph.commercial_analytics import analyze_security_portfolio
from xdr_graph.models import IncidentReport


def report(incident_id: str, event_id: str, risk: int, *, minutes_ago: int) -> IncidentReport:
    timestamp = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()
    return IncidentReport.model_validate({
        "incident_id": incident_id,
        "verdict": "suspicious" if risk >= 70 else "needs_review",
        "risk_score": risk,
        "evidence": ["PowerShell external connection"],
        "recommended_actions": [],
        "validation": {"passed": True, "errors": [], "review_count": 0},
        "findings": [{
            "source": "behavior", "rule_id": f"rule-{incident_id}", "severity": risk,
            "reason": "suspicious process chain", "event_ids": [event_id],
            "references": [{"framework": "mitre_attack", "external_id": "T1059.001"}],
        }],
        "source_events": [{
            "event_id": event_id, "event_type": "network_connect", "timestamp": timestamp,
            "process_name": "powershell.exe", "user": "local-user",
            "destination_ip": "8.8.8.8", "destination_port": 443, "protocol": "tcp",
        }],
    })


def test_entity_risk_and_attack_stories_correlate_shared_local_evidence():
    result = analyze_security_portfolio([
        report("incident-a", "event-a", 88, minutes_ago=5),
        report("incident-b", "event-b", 76, minutes_ago=15),
    ], window_hours=24)

    assert result["privacy"] == "local_only"
    process = next(item for item in result["entities"] if item["value"] == "powershell.exe")
    assert process["incident_count"] == 2
    assert process["risk_score"] >= 70
    story = result["stories"][0]
    assert story["incident_count"] == 2
    assert story["confidence"] > 50
    assert story["mitre_techniques"] == ["T1059.001"]


def test_hunting_window_is_bounded_to_supported_product_ranges():
    with pytest.raises(ValueError, match="time window"):
        analyze_security_portfolio([], window_hours=2)
