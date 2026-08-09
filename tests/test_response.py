import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from xdr_graph.response import (
    ApprovalService,
    CollectEvidenceCommand,
    DryRunResponseService,
    QuarantineFileCommand,
    TerminateProcessCommand,
    load_default_response_policy,
)
from xdr_graph.workflow import build_workflow


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"
REQUESTED_AT = datetime(2026, 8, 9, 1, 0, tzinfo=timezone.utc)


def suspicious_report():
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    return build_workflow().invoke(
        {
            "raw_incident": {
                "incident_id": raw_batch["incident_id"],
                "events": raw_batch["events"],
            },
            "findings": [],
        }
    )["report"]


def review_report():
    return build_workflow().invoke(
        {
            "raw_incident": {
                "incident_id": "review-incident",
                "events": [
                    {
                        "event_id": "review-event",
                        "event_type": "process_start",
                        "timestamp": "2026-08-09T10:00:00+09:00",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -enc TEST",
                    }
                ],
            },
            "findings": [],
        }
    )["report"]


def terminate_command(**changes):
    values = {
        "command_id": "terminate-001",
        "incident_id": "incident-001",
        "action": "terminate_process",
        "requested_at": REQUESTED_AT,
        "process_id": 4242,
        "process_start_time": REQUESTED_AT,
        "process_image_path": "C:\\Tools\\powershell.exe",
    }
    values.update(changes)
    return TerminateProcessCommand(**values)


def quarantine_command(**changes):
    values = {
        "command_id": "quarantine-001",
        "incident_id": "incident-001",
        "action": "quarantine_file",
        "requested_at": REQUESTED_AT,
        "file_path": "C:\\Users\\user\\Downloads\\payload.exe",
        "sha256": "a" * 64,
    }
    values.update(changes)
    return QuarantineFileCommand(**values)


def test_response_command_schema_requires_timezone_and_valid_hash():
    with pytest.raises(ValidationError, match="timezone offset"):
        terminate_command(requested_at=datetime(2026, 8, 9, 1, 0))
    with pytest.raises(ValidationError, match="sha256"):
        quarantine_command(sha256="not-a-hash")


def test_dry_run_allows_valid_target_without_executing_it():
    preview = DryRunResponseService().preview(terminate_command(), suspicious_report())

    assert preview.allowed is True
    assert preview.executed is False
    assert preview.approval_required is True
    assert preview.reasons == ["dry-run validation passed; no system change was performed"]


@pytest.mark.parametrize(
    "command",
    [
        terminate_command(
            command_id="protected-process",
            process_image_path="C:\\Windows\\System32\\lsass.exe",
        ),
        quarantine_command(
            command_id="protected-file",
            file_path="C:\\Windows\\System32\\kernel32.dll",
        ),
    ],
)
def test_protected_system_targets_are_blocked(command):
    preview = DryRunResponseService().preview(command, suspicious_report())

    assert preview.allowed is False
    assert preview.executed is False
    assert any("protected system" in reason for reason in preview.reasons)


def test_command_must_match_verified_report_and_recommended_action():
    preview = DryRunResponseService().preview(
        terminate_command(incident_id="different-incident"), review_report()
    )

    assert preview.allowed is False
    assert "command incident does not match report incident" in preview.reasons
    assert "action was not recommended by the verified incident report" in preview.reasons


def test_evidence_collection_only_accepts_events_from_the_incident():
    valid_command = CollectEvidenceCommand(
        command_id="collect-001",
        incident_id="review-incident",
        action="collect_additional_evidence",
        requested_at=REQUESTED_AT,
        event_ids=["review-event"],
    )
    invalid_command = valid_command.model_copy(
        update={"command_id": "collect-002", "event_ids": ["unknown-event"]}
    )
    service = DryRunResponseService()

    assert service.preview(valid_command, review_report()).allowed is True
    assert service.preview(invalid_command, review_report()).allowed is False


def test_approval_is_bound_to_command_and_expires():
    clock_value = {"now": REQUESTED_AT}
    policy = load_default_response_policy()
    approval_service = ApprovalService(policy, clock=lambda: clock_value["now"])
    preview = DryRunResponseService(policy).preview(
        terminate_command(), suspicious_report()
    )
    approval = approval_service.request(preview)

    assert approval.status == "pending"
    assert approval_service.authorize(approval.approval_id, "terminate-001") is False
    approved = approval_service.decide(
        approval.approval_id, approve=True, approver="local-user"
    )
    assert approved.status == "approved"
    assert approval_service.authorize(approval.approval_id, "terminate-001") is True
    assert approval_service.authorize(approval.approval_id, "different-command") is False

    clock_value["now"] += timedelta(minutes=11)
    assert approval_service.authorize(approval.approval_id, "terminate-001") is False

    clock_value["now"] = REQUESTED_AT
    second_preview = preview.model_copy(update={"command_id": "terminate-expiring"})
    expiring = approval_service.request(second_preview)
    clock_value["now"] += timedelta(minutes=11)
    assert approval_service.authorize(expiring.approval_id, "terminate-expiring") is False


def test_blocked_preview_cannot_request_approval():
    preview = DryRunResponseService().preview(
        terminate_command(process_image_path="C:\\Windows\\System32\\lsass.exe"),
        suspicious_report(),
    )

    with pytest.raises(ValueError, match="blocked dry-run"):
        ApprovalService().request(preview)
