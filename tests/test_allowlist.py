from datetime import datetime, timezone

import pytest

from xdr_graph.allowlist import (
    AllowlistEngine,
    AllowlistEntry,
    AllowlistMatch,
    AllowlistPolicy,
)
from xdr_graph.workflow import build_workflow


RAW_INCIDENT = {
    "incident_id": "allowlist-incident",
    "events": [
        {
            "event_id": "process-allowed",
            "event_type": "process_start",
            "timestamp": "2026-08-09T10:00:00+09:00",
            "host_id": "desktop-001",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -enc SAFE_INTERNAL_TASK",
        }
    ],
}


def make_engine(*, expires_at: datetime, approved: bool = True) -> AllowlistEngine:
    policy = AllowlistPolicy(
        policy_version="test-policy",
        entries=[
            AllowlistEntry(
                entry_id="approved-maintenance-task",
                reason="Known internal maintenance task",
                enabled=True,
                reviewer_approved=approved,
                expires_at=expires_at,
                match=AllowlistMatch(
                    rule_ids=["PROC-002"],
                    host_ids=["desktop-001"],
                    process_names=["powershell.exe"],
                ),
            )
        ],
    )
    return AllowlistEngine(
        policy, clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc)
    )


def test_approved_allowlist_suppresses_score_but_preserves_full_trace():
    result = build_workflow(
        allowlist_engine=make_engine(
            expires_at=datetime(2026, 9, 1, tzinfo=timezone.utc)
        )
    ).invoke({"raw_incident": RAW_INCIDENT, "findings": []})
    report = result["report"]

    assert report.verdict == "benign"
    assert report.risk_score == 0
    assert report.findings == []
    assert report.suppressed_findings[0].finding.rule_id == "PROC-002"
    assert report.suppressed_findings[0].allowlist_entry_id == "approved-maintenance-task"
    assert report.source_events[0].event_id == "process-allowed"


@pytest.mark.parametrize(
    ("expires_at", "approved"),
    [
        (datetime(2026, 8, 1, tzinfo=timezone.utc), True),
        (datetime(2026, 9, 1, tzinfo=timezone.utc), False),
    ],
)
def test_expired_or_unapproved_entry_cannot_hide_a_detection(expires_at, approved):
    report = build_workflow(
        allowlist_engine=make_engine(expires_at=expires_at, approved=approved)
    ).invoke({"raw_incident": RAW_INCIDENT, "findings": []})["report"]

    assert report.verdict == "needs_review"
    assert report.risk_score == 35
    assert report.findings[0].rule_id == "PROC-002"
    assert report.suppressed_findings == []


def test_rule_only_allowlist_is_rejected_as_too_broad():
    with pytest.raises(ValueError, match="event selector"):
        AllowlistMatch(rule_ids=["PROC-002"])


def test_report_links_findings_chains_and_original_events():
    incident = {
        "incident_id": "trace-incident",
        "events": [
            {
                "event_id": "trace-process",
                "event_type": "process_start",
                "timestamp": "2026-08-09T10:00:00+09:00",
                "process_name": "powershell.exe",
                "process_id": 10,
                "process_start_time": "2026-08-09T10:00:00+09:00",
                "parent_process": "WINWORD.EXE",
                "command_line": "powershell.exe -enc TEST",
            },
            {
                "event_id": "trace-file",
                "event_type": "file_create",
                "timestamp": "2026-08-09T10:00:01+09:00",
                "process_name": "powershell.exe",
                "process_id": 10,
                "process_start_time": "2026-08-09T10:00:00+09:00",
                "file_path": "C:\\Temp\\trace.exe",
            },
        ],
    }
    report = build_workflow().invoke(
        {"raw_incident": incident, "findings": []}
    )["report"]

    source_ids = {event.event_id for event in report.source_events}
    assert report.attack_chains[0].evidence_event_ids == ["trace-process", "trace-file"]
    assert all(set(finding.event_ids) <= source_ids for finding in report.findings)
    assert report.findings[0].references
