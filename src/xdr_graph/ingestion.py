from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from xdr_graph.models import IncidentReport, SecurityEvent
from xdr_graph.audit import AuditLogger
from xdr_graph.workflow import build_workflow


class NormalizedEventBatch(BaseModel):
    """수집기가 분석 그래프에 전달하는 정규화 이벤트 묶음."""

    # 이 객체는 수집기와 분석기의 경계 계약이다. 수집기별 임의 필드는
    # 원본 저장소에 남기고, 그래프에는 합의된 필드만 전달한다.
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    batch_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    collector_id: str = Field(min_length=1)
    received_at: datetime
    events: list[SecurityEvent] = Field(min_length=1)

    @field_validator("received_at")
    @classmethod
    def require_received_at_timezone(cls, value: datetime) -> datetime:
        # 수집 시각은 이벤트 시각과 지연 시간을 비교할 때 사용한다.
        # 다른 시간대의 장비에서도 비교할 수 있도록 UTC 오프셋을 필수로 한다.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("received_at must include a timezone offset")
        return value

    @model_validator(mode="after")
    def reject_duplicate_event_ids(self) -> "NormalizedEventBatch":
        # 같은 배치의 중복 이벤트를 그대로 분석하면 위험 점수가 중복 합산된다.
        # 배치 간 중복 제거는 저장·버퍼 단계에서 구현하고, 여기서는 배치 내부만 막는다.
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id must be unique within a batch")
        return self


class IngestionReceipt(BaseModel):
    """입력 배치가 그래프에서 처리됐음을 수집기에 돌려주는 결과."""

    batch_id: str
    incident_id: str
    accepted_event_count: int
    # 수집기는 재전송이 흔하므로 저장소에서 걸러진 개수를 따로 알려준다.
    # 기본값을 두어 저장소를 쓰지 않는 기존 그래프 입력 경로와도 호환한다.
    duplicate_event_count: int = 0
    analyzed: bool = True
    report: IncidentReport


class EventBatchSink(Protocol):
    """향후 Sysmon 등 모든 수집기가 의존할 입력 포트."""

    def submit(self, batch: NormalizedEventBatch) -> IngestionReceipt: ...


class GraphIngestionService:
    """검증된 이벤트 배치를 현재 LangGraph 사건 흐름에 연결한다."""

    def __init__(
        self,
        workflow: CompiledStateGraph | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        # 테스트나 향후 운영 설정에서 다른 모델 구성을 주입할 수 있게 한다.
        # 지정하지 않으면 안전한 규칙 기반 그래프를 사용한다.
        self.workflow = workflow or build_workflow()
        self.audit_logger = audit_logger

    def submit_raw(self, raw_batch: dict[str, Any]) -> IngestionReceipt:
        # 외부 수집기 입력은 신뢰하지 않고 Pydantic 계약을 먼저 통과시킨다.
        return self.submit(NormalizedEventBatch.model_validate(raw_batch))

    def submit(self, batch: NormalizedEventBatch) -> IngestionReceipt:
        incident_payload = {
            "incident_id": batch.incident_id,
            "events": [event.model_dump(mode="json") for event in batch.events],
        }
        graph_result = self.workflow.invoke(
            {"raw_incident": incident_payload, "findings": []}
        )
        receipt = IngestionReceipt(
            batch_id=batch.batch_id,
            incident_id=batch.incident_id,
            accepted_event_count=len(batch.events),
            report=graph_result["report"],
        )
        if self.audit_logger:
            # 원본 명령줄 전체 대신 사건·배치 식별자와 판정 요약을 남겨 감사성과
            # 개인정보 최소화를 동시에 유지한다. 상세 원본은 사건 저장소에서 추적한다.
            self.audit_logger.record(
                "analysis",
                "graph_analysis",
                "succeeded",
                {
                    "batch_id": batch.batch_id,
                    "incident_id": batch.incident_id,
                    "event_count": len(batch.events),
                    "verdict": receipt.report.verdict,
                    "risk_score": receipt.report.risk_score,
                },
            )
        return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit a normalized event batch")
    parser.add_argument("batch", type=Path, help="Path to a normalized batch JSON file")
    args = parser.parse_args()

    raw_batch = json.loads(args.batch.read_text(encoding="utf-8"))
    receipt = GraphIngestionService().submit_raw(raw_batch)
    print(receipt.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
