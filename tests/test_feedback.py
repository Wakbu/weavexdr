from datetime import datetime, timezone

import pytest

from xdr_graph.allowlist import AllowlistMatch, AllowlistPolicy
from xdr_graph.evaluation import EvaluationCase, ExpectedOutcome
from xdr_graph.feedback import (
    DetectionFeedback,
    FeedbackReviewService,
    SQLiteFeedbackStore,
)
from xdr_graph.models import IncidentInput


def make_feedback(number: int, *, approved: bool = True) -> DetectionFeedback:
    incident = IncidentInput(
        incident_id=f"feedback-incident-{number}",
        events=[
            {
                "event_id": f"feedback-event-{number}",
                "event_type": "process_start",
                "timestamp": "2026-08-09T10:00:00+09:00",
                "host_id": "maintenance-host",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc APPROVED_TASK",
            }
        ],
    )
    return DetectionFeedback(
        feedback_id=f"feedback-{number}",
        incident_id=incident.incident_id,
        rule_id="PROC-002",
        label="false_positive",
        reason="Approved maintenance automation",
        selector=AllowlistMatch(
            rule_ids=["PROC-002"],
            host_ids=["maintenance-host"],
            process_names=["powershell.exe"],
        ),
        evaluation_case=EvaluationCase(
            case_id=f"feedback-eval-{number}",
            description="Approved maintenance automation must remain benign",
            incident=incident,
            expected=ExpectedOutcome(
                verdict="benign", min_score=0, max_score=0, required_rule_ids=[]
            ),
        ),
        submitted_at=datetime(2026, 8, 9, 1, number, tzinfo=timezone.utc),
        reviewer_approved=approved,
    )


def test_feedback_is_persisted_and_duplicate_ids_are_idempotent():
    with SQLiteFeedbackStore(":memory:") as store:
        feedback = make_feedback(1)
        store.save(feedback)
        store.save(feedback)

        assert store.list_all() == [feedback]


def test_two_approved_incidents_create_reviewable_policy_and_evaluation_proposal():
    feedback_items = [make_feedback(1), make_feedback(2), make_feedback(3, approved=False)]
    service = FeedbackReviewService(minimum_confirmations=2)

    proposals = service.propose(feedback_items)

    assert len(proposals) == 1
    assert proposals[0].source_feedback_ids == ["feedback-1", "feedback-2"]
    assert proposals[0].allowlist_entry.reviewer_approved is True
    assert [case.case_id for case in proposals[0].evaluation_cases] == [
        "feedback-eval-1",
        "feedback-eval-2",
    ]

    policy = AllowlistPolicy(policy_version="test", entries=[])
    with pytest.raises(PermissionError, match="explicit confirmation"):
        service.merge_approved(proposals[0], policy, [], confirmed=False)

    updated_policy, updated_cases = service.merge_approved(
        proposals[0], policy, [], confirmed=True
    )
    assert updated_policy.entries[0].entry_id.startswith("feedback-")
    assert len(updated_cases) == 2
