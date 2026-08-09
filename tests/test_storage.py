import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from xdr_graph.ingestion import IngestionReceipt, NormalizedEventBatch
from xdr_graph.storage import (
    BufferFullError,
    EventBuffer,
    PersistentIngestionService,
    SQLiteEventStore,
)


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def load_sample_batch() -> dict:
    return json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))


def make_batch(batch_id: str, event_indexes: list[int]) -> NormalizedEventBatch:
    raw_batch = load_sample_batch()
    raw_batch["batch_id"] = batch_id
    raw_batch["events"] = [raw_batch["events"][index] for index in event_indexes]
    return NormalizedEventBatch.model_validate(raw_batch)


def test_incident_is_reanalyzed_with_events_from_multiple_batches():
    with SQLiteEventStore(":memory:") as store:
        service = PersistentIngestionService(store)

        first_receipt = service.submit(make_batch("batch-first", [0]))
        second_batch = make_batch("batch-second", [0, 1])
        second_receipt = service.submit(second_batch)

        assert first_receipt.accepted_event_count == 1
        assert second_receipt.accepted_event_count == 1
        assert second_receipt.duplicate_event_count == 1
        assert second_receipt.report.risk_score > first_receipt.report.risk_score
        assert store.stats().events == 2
        assert [event.event_id for event in store.load_incident_events("incident-001")] == [
            "event-001",
            "event-002",
        ]


def test_duplicate_only_batch_reuses_the_last_report_without_analysis():
    with SQLiteEventStore(":memory:") as store:
        service = PersistentIngestionService(store)
        first_receipt = service.submit(make_batch("batch-original", [0, 1]))

        duplicate_receipt = service.submit(make_batch("batch-retry", [0, 1]))

        assert duplicate_receipt.accepted_event_count == 0
        assert duplicate_receipt.duplicate_event_count == 2
        assert duplicate_receipt.analyzed is False
        assert duplicate_receipt.report == first_receipt.report
        assert store.stats().events == 2
        assert store.stats().batches == 2


def test_incident_listing_and_stats_apply_server_side_filters():
    with SQLiteEventStore(":memory:") as store:
        service = PersistentIngestionService(store)
        service.submit(make_batch("batch-filter", [0, 1]))

        stats = store.incident_stats(query="powershell")
        assert stats["total"] == 1
        assert stats["filtered_total"] == 1
        assert stats["verdicts"]["suspicious"] == 1
        assert store.incident_stats(query="missing")["filtered_total"] == 0
        assert len(store.list_incident_reports(limit=50, query="powershell")) == 1
        assert store.list_incident_reports(limit=50, query="missing") == []
        assert store.list_incident_reports(limit=50, verdict="benign") == []


def test_incident_stats_are_not_truncated_to_the_default_list_limit():
    with SQLiteEventStore(":memory:") as store:
        service = PersistentIngestionService(store)
        for incident_number in range(105):
            batch = make_batch(f"batch-{incident_number}", [0]).model_copy(
                update={"incident_id": f"incident-{incident_number:03d}"}
            )
            # 같은 샘플 이벤트 ID는 중복으로 처리되므로 사건마다 고유 ID를 부여한다.
            batch.events[0].event_id = f"event-{incident_number:03d}"
            service.submit(batch)

        assert len(store.list_incident_reports()) == 100
        assert store.incident_stats()["total"] == 105
        assert store.incident_stats()["filtered_total"] == 105


def test_event_buffer_enforces_capacity_and_flushes_oldest_batch_first():
    class RecordingSink:
        def __init__(self) -> None:
            self.batch_ids: list[str] = []

        def submit(self, batch: NormalizedEventBatch) -> IngestionReceipt:
            self.batch_ids.append(batch.batch_id)
            # 실제 보고서를 간단히 재사용해 이 테스트는 버퍼 순서에만 집중한다.
            with SQLiteEventStore(":memory:") as store:
                return PersistentIngestionService(store).submit(batch)

    sink = RecordingSink()
    event_buffer = EventBuffer(sink, capacity=2)
    event_buffer.enqueue(make_batch("batch-one", [0]))
    event_buffer.enqueue(make_batch("batch-two", [1]))

    with pytest.raises(BufferFullError, match="capacity exceeded"):
        event_buffer.enqueue(make_batch("batch-three", [2]))

    receipts = event_buffer.flush()
    assert [receipt.batch_id for receipt in receipts] == ["batch-one", "batch-two"]
    assert sink.batch_ids == ["batch-one", "batch-two"]
    assert event_buffer.queued_event_count == 0


def test_failed_flush_keeps_the_batch_for_retry():
    class FailingSink:
        def submit(self, batch: NormalizedEventBatch) -> IngestionReceipt:
            raise RuntimeError("temporary failure")

    event_buffer = EventBuffer(FailingSink(), capacity=3)
    event_buffer.enqueue(make_batch("batch-pending", [0, 1]))

    with pytest.raises(RuntimeError, match="temporary failure"):
        event_buffer.flush()

    assert event_buffer.queued_batch_count == 1
    assert event_buffer.queued_event_count == 2


def test_cleanup_removes_records_older_than_the_retention_period():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with SQLiteEventStore(
        ":memory:", retention_days=30, clock=lambda: current_time
    ) as store:
        PersistentIngestionService(store).submit(make_batch("batch-old", [0]))

        removed = store.cleanup_expired(
            now=datetime(2026, 2, 1, tzinfo=timezone.utc)
        )

        assert removed.events == 1
        assert removed.batches == 1
        assert removed.incidents == 1
        assert store.stats().events == 0


def test_ingestion_runs_retention_cleanup_automatically_when_due():
    clock_value = {"now": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    with SQLiteEventStore(
        ":memory:", retention_days=30, clock=lambda: clock_value["now"]
    ) as store:
        service = PersistentIngestionService(store)
        service.submit(make_batch("batch-old", [0]))

        clock_value["now"] = datetime(2026, 2, 1, tzinfo=timezone.utc)
        new_batch = make_batch("batch-new", [0])
        new_batch = new_batch.model_copy(update={"incident_id": "incident-new"})
        service.submit(new_batch)

        # 오래된 사건은 새 배치를 받기 전에 지워지고 새 사건 한 건만 남는다.
        assert store.stats().events == 1
        assert store.stats().batches == 1
        assert store.stats().incidents == 1
