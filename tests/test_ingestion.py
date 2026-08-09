import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from xdr_graph.ingestion import GraphIngestionService, NormalizedEventBatch


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def load_sample_batch() -> dict:
    # 매 테스트가 독립적으로 값을 수정할 수 있도록 파일에서 새 객체를 읽는다.
    return json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))


def test_normalized_batch_reaches_the_graph():
    receipt = GraphIngestionService().submit_raw(load_sample_batch())

    assert receipt.batch_id == "batch-001"
    assert receipt.incident_id == "incident-001"
    assert receipt.accepted_event_count == 3
    assert receipt.report.verdict == "suspicious"
    assert receipt.report.risk_score == 100


def test_duplicate_event_ids_are_rejected_before_analysis():
    raw_batch = load_sample_batch()
    raw_batch["events"][1]["event_id"] = raw_batch["events"][0]["event_id"]

    with pytest.raises(ValidationError, match="unique within a batch"):
        NormalizedEventBatch.model_validate(raw_batch)


def test_batch_received_at_requires_a_timezone():
    raw_batch = load_sample_batch()
    raw_batch["received_at"] = "2026-08-09T10:00:10"

    with pytest.raises(ValidationError, match="timezone offset"):
        NormalizedEventBatch.model_validate(raw_batch)


def test_malformed_event_is_rejected_at_the_input_boundary():
    raw_batch = load_sample_batch()
    del raw_batch["events"][2]["destination_ip"]

    with pytest.raises(ValidationError, match="destination_ip"):
        GraphIngestionService().submit_raw(raw_batch)
