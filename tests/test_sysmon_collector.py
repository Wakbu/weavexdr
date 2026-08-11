from __future__ import annotations

import time
from datetime import datetime, timezone

from xdr_graph.sysmon_collector import SysmonCollector, SysmonLogRecord
from xdr_graph.sysmon_parser import SysmonXmlParser
from tests.test_sysmon_parser import process_create_xml


class FakeReader:
    def __init__(self, records: list[SysmonLogRecord]) -> None:
        self.records = records

    def latest_record_id(self) -> int:
        return 1000

    def read_after(self, record_id: int) -> list[SysmonLogRecord]:
        ready = [record for record in self.records if record.record_id > record_id]
        self.records = [record for record in self.records if record not in ready]
        return ready


class RecordingSink:
    def __init__(self) -> None:
        self.batches = []

    def submit(self, batch):
        self.batches.append(batch)


class RetryReader:
    """커서가 전진하기 전에는 같은 Windows 이벤트를 다시 반환한다."""

    def __init__(self, record: SysmonLogRecord) -> None:
        self.record = record

    def latest_record_id(self) -> int:
        return 1000

    def read_after(self, record_id: int) -> list[SysmonLogRecord]:
        return [self.record] if record_id < self.record.record_id else []


class FailOnceSink(RecordingSink):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def submit(self, batch):
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("temporary storage failure")
        super().submit(batch)


def test_collector_submits_new_events_and_reports_running_state():
    sink = RecordingSink()
    statuses: list[dict[str, object]] = []
    reader = FakeReader([SysmonLogRecord(1001, process_create_xml())])
    collector = SysmonCollector(
        sink,
        reader_factory=lambda: reader,
        status_callback=statuses.append,
        poll_interval=0.01,
    )

    collector.start()
    deadline = time.monotonic() + 1
    while not sink.batches and time.monotonic() < deadline:
        time.sleep(0.01)
    assert collector.stop(timeout=1)

    assert len(sink.batches) == 1
    batch = sink.batches[0]
    assert batch.batch_id == "sysmon-batch-1001"
    assert batch.incident_id.startswith("sysmon-desktop-test-")
    assert batch.received_at.tzinfo == timezone.utc
    assert any(status["state"] == "running" for status in statuses)
    assert statuses[-1]["state"] == "stopped"


def test_incident_id_uses_process_guid_for_related_events():
    event = SysmonXmlParser().parse(process_create_xml())

    incident_id = SysmonCollector._incident_id(event)

    assert incident_id == "sysmon-desktop-test-11111111-2222-3333-4444-555555555555"


def test_collector_surfaces_reader_failure_without_crashing():
    statuses: list[dict[str, object]] = []

    def fail_reader():
        raise ModuleNotFoundError("win32evtlog")

    collector = SysmonCollector(
        RecordingSink(),
        reader_factory=fail_reader,
        status_callback=statuses.append,
        poll_interval=0.01,
    )
    collector.start()
    deadline = time.monotonic() + 1
    while not any(status["state"] == "error" for status in statuses) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert collector.stop(timeout=1)

    error_status = next(status for status in statuses if status["state"] == "error")
    assert error_status["label"] == "Windows 이벤트 로그 모듈 누락"


def test_collector_retries_event_when_submission_fails_before_cursor_advance():
    sink = FailOnceSink()
    reader = RetryReader(SysmonLogRecord(1001, process_create_xml()))
    collector = SysmonCollector(
        sink,
        reader_factory=lambda: reader,
        poll_interval=0.01,
    )

    collector.start()
    deadline = time.monotonic() + 1
    while not sink.batches and time.monotonic() < deadline:
        time.sleep(0.01)
    assert collector.stop(timeout=1)

    assert sink.attempts >= 2
    assert [batch.batch_id for batch in sink.batches] == ["sysmon-batch-1001"]


def test_collector_pause_and_resume_publish_consistent_status():
    statuses = []
    collector = SysmonCollector(
        FailOnceSink(),
        reader_factory=lambda: RetryReader(SysmonLogRecord(1001, process_create_xml())),
        status_callback=statuses.append,
        poll_interval=0.01,
    )
    collector.pause()
    assert collector.paused is True
    assert statuses[-1]["state"] == "paused"
    collector.resume()
    assert collector.paused is False
    assert statuses[-1]["state"] == "running"
