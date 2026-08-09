from __future__ import annotations

import hashlib
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from xdr_graph.allowlist import AllowlistEntry, AllowlistMatch, AllowlistPolicy
from xdr_graph.evaluation import EvaluationCase


class DetectionFeedback(BaseModel):
    """사용자가 검토한 탐지와 재현 가능한 평가 사건을 함께 보존한다."""

    model_config = ConfigDict(extra="forbid")

    feedback_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    label: Literal["false_positive", "true_positive"]
    reason: str = Field(min_length=1)
    selector: AllowlistMatch
    evaluation_case: EvaluationCase
    submitted_at: datetime
    reviewer_approved: bool = False

    @field_validator("submitted_at")
    @classmethod
    def require_submitted_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("feedback timestamp must include a timezone offset")
        return value


class FeedbackProposal(BaseModel):
    proposal_id: str
    source_feedback_ids: list[str]
    allowlist_entry: AllowlistEntry
    evaluation_cases: list[EvaluationCase]


class SQLiteFeedbackStore:
    """오탐·정탐 검토 기록을 사건 DB와 같은 SQLite 파일에 저장할 수 있다."""

    def __init__(self, database_path: str | Path = "data/xdr.db") -> None:
        database_name = str(database_path)
        if database_name != ":memory:":
            Path(database_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(database_name, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS detection_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    feedback_json TEXT NOT NULL,
                    submitted_at TEXT NOT NULL
                )
                """
            )

    def save(self, feedback: DetectionFeedback) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO detection_feedback (
                    feedback_id, incident_id, rule_id, label,
                    feedback_json, submitted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(feedback_id) DO NOTHING
                """,
                (
                    feedback.feedback_id,
                    feedback.incident_id,
                    feedback.rule_id,
                    feedback.label,
                    feedback.model_dump_json(),
                    feedback.submitted_at.astimezone(timezone.utc).isoformat(),
                ),
            )

    def list_all(self) -> list[DetectionFeedback]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT feedback_json FROM detection_feedback ORDER BY submitted_at, feedback_id"
            ).fetchall()
        return [
            DetectionFeedback.model_validate_json(row["feedback_json"]) for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteFeedbackStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class FeedbackReviewService:
    """반복 확인된 오탐만 허용 목록·평가 데이터 변경 후보로 만든다."""

    def __init__(
        self,
        *,
        minimum_confirmations: int = 2,
        allowlist_days: int = 30,
    ) -> None:
        if minimum_confirmations < 2:
            # 한 번의 오판이나 공격자가 만든 피드백으로 탐지 규칙이 꺼지는 것을 막는다.
            raise ValueError("minimum_confirmations must be at least 2")
        if allowlist_days < 1:
            raise ValueError("allowlist_days must be at least 1")
        self.minimum_confirmations = minimum_confirmations
        self.allowlist_days = allowlist_days

    def propose(self, feedback_items: Sequence[DetectionFeedback]) -> list[FeedbackProposal]:
        grouped: dict[str, list[DetectionFeedback]] = defaultdict(list)
        for feedback in feedback_items:
            if feedback.label != "false_positive" or not feedback.reviewer_approved:
                continue
            selector_key = feedback.selector.model_dump_json()
            grouped[f"{feedback.rule_id}|{selector_key}"].append(feedback)

        proposals: list[FeedbackProposal] = []
        for group_key, group in grouped.items():
            distinct_incidents = {feedback.incident_id for feedback in group}
            if len(distinct_incidents) < self.minimum_confirmations:
                continue
            group.sort(key=lambda feedback: (feedback.submitted_at, feedback.feedback_id))
            digest = hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:12]
            latest_time = max(feedback.submitted_at for feedback in group)
            proposals.append(
                FeedbackProposal(
                    proposal_id=f"proposal-{digest}",
                    source_feedback_ids=[feedback.feedback_id for feedback in group],
                    allowlist_entry=AllowlistEntry(
                        entry_id=f"feedback-{digest}",
                        reason=f"Repeated reviewer-approved false positive for {group[0].rule_id}",
                        enabled=True,
                        reviewer_approved=True,
                        expires_at=latest_time + timedelta(days=self.allowlist_days),
                        match=group[0].selector,
                    ),
                    evaluation_cases=[feedback.evaluation_case for feedback in group],
                )
            )
        return proposals

    @staticmethod
    def merge_approved(
        proposal: FeedbackProposal,
        allowlist_policy: AllowlistPolicy,
        evaluation_cases: Sequence[EvaluationCase],
        *,
        confirmed: bool,
    ) -> tuple[AllowlistPolicy, list[EvaluationCase]]:
        if not confirmed:
            raise PermissionError("feedback proposal requires explicit confirmation")
        # 원본 객체를 직접 바꾸지 않아 검토 또는 테스트 실패 시 기존 정책을 그대로 유지한다.
        updated_policy = allowlist_policy.model_copy(
            update={"entries": [*allowlist_policy.entries, proposal.allowlist_entry]}
        )
        updated_policy = AllowlistPolicy.model_validate(updated_policy.model_dump())
        existing_case_ids = {case.case_id for case in evaluation_cases}
        new_cases = [
            case
            for case in proposal.evaluation_cases
            if case.case_id not in existing_case_ids
        ]
        return updated_policy, [*evaluation_cases, *new_cases]
