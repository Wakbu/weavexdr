from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event, Thread
from typing import Protocol
from xml.etree import ElementTree

from xdr_graph.ingestion import EventBatchSink, NormalizedEventBatch
from xdr_graph.models import SecurityEvent
from xdr_graph.sysmon_parser import WINDOWS_EVENT_NAMESPACE, SysmonXmlParser


SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True)
class SysmonLogRecord:
    """Windows 이벤트 로그에서 읽은 레코드 ID와 원본 XML이다."""

    record_id: int
    xml: str


class SysmonEventReader(Protocol):
    """운영체제 의존 로그 읽기와 수집 루프를 분리하는 최소 인터페이스다."""

    def latest_record_id(self) -> int: ...

    def read_after(self, record_id: int) -> list[SysmonLogRecord]: ...


class WindowsEventLogReader:
    """pywin32의 Windows Event Log API로 새 Sysmon XML만 읽는다."""

    def __init__(self, log_name: str = SYSMON_LOG_NAME) -> None:
        # 비 Windows 테스트와 API 자체 실행을 막지 않도록 운영체제 모듈은
        # 실제 수집기를 만들 때만 불러온다.
        import pywintypes
        import win32evtlog

        self.log_name = log_name
        self._event_log = win32evtlog
        self._windows_error = pywintypes.error

    def latest_record_id(self) -> int:
        query = "*[System[EventRecordID > 0]]"
        flags = self._event_log.EvtQueryChannelPath | self._event_log.EvtQueryReverseDirection
        handle = self._event_log.EvtQuery(self.log_name, flags, query)
        try:
            events = self._next(handle, 1)
            if not events:
                return 0
            try:
                xml = self._event_log.EvtRender(events[0], self._event_log.EvtRenderEventXml)
                return self._record_id(xml)
            finally:
                self._close_all(events)
        finally:
            self._close(handle)

    def read_after(self, record_id: int) -> list[SysmonLogRecord]:
        # 지원 이벤트와 레코드 커서를 로그 엔진에서 먼저 필터링해 Python으로
        # 불필요한 전체 이벤트 XML을 가져오지 않는다.
        query = (
            "*[System[((EventID=1 or EventID=3 or EventID=11) "
            f"and EventRecordID > {record_id})]]"
        )
        flags = self._event_log.EvtQueryChannelPath | self._event_log.EvtQueryForwardDirection
        handle = self._event_log.EvtQuery(self.log_name, flags, query)
        records: list[SysmonLogRecord] = []
        try:
            while True:
                events = self._next(handle, 64)
                if not events:
                    break
                try:
                    for event in events:
                        xml = self._event_log.EvtRender(event, self._event_log.EvtRenderEventXml)
                        records.append(SysmonLogRecord(self._record_id(xml), xml))
                finally:
                    self._close_all(events)
        finally:
            self._close(handle)
        return records

    def _next(self, handle, count: int) -> list:
        try:
            return list(self._event_log.EvtNext(handle, count, 0, 0))
        except self._windows_error as error:
            error_code = getattr(error, "winerror", None) or error.args[0]
            if error_code == 259:  # ERROR_NO_MORE_ITEMS
                return []
            raise

    def _close_all(self, handles: list) -> None:
        for handle in handles:
            self._close(handle)

    @staticmethod
    def _close(handle) -> None:
        close = getattr(handle, "Close", None)
        if close:
            close()

    @staticmethod
    def _record_id(xml: str) -> int:
        root = ElementTree.fromstring(xml)
        value = root.findtext(
            "./event:System/event:EventRecordID",
            namespaces=WINDOWS_EVENT_NAMESPACE,
        )
        if not value:
            raise ValueError("Sysmon EventRecordID is required")
        return int(value)


class SysmonCollector:
    """새 Sysmon 이벤트를 기존 영속 수집·분석 파이프라인에 연결한다."""

    def __init__(
        self,
        sink: EventBatchSink,
        *,
        reader_factory: Callable[[], SysmonEventReader] = WindowsEventLogReader,
        status_callback: Callable[[dict[str, object]], None] | None = None,
        poll_interval: float = 1.0,
        logger: logging.Logger | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.sink = sink
        self.reader_factory = reader_factory
        self.status_callback = status_callback
        self.poll_interval = poll_interval
        self.logger = logger or logging.getLogger(__name__)
        self._stop_event = Event()
        self._pause_event = Event()
        self._thread: Thread | None = None
        self._parser = SysmonXmlParser()
        self._processed_count = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._publish_status("starting", "Sysmon 수집기 시작 중")
        self._thread = Thread(target=self._run, name="weavexdr-sysmon", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 15.0) -> bool:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        stopped = not self._thread or not self._thread.is_alive()
        if stopped:
            self._publish_status("stopped", "Sysmon 수집기 종료됨")
        return stopped

    def pause(self) -> None:
        # 커서를 폐기하지 않고 읽기만 멈춰 재개 시 중간 이벤트를 유실하지 않는다.
        self._pause_event.set()
        self._publish_status("paused", "Sysmon 수집 일시정지")

    def resume(self) -> None:
        self._pause_event.clear()
        self._publish_status("running", "실시간 Sysmon 수집 중")

    @property
    def paused(self) -> bool:
        return self._pause_event.is_set()

    def _run(self) -> None:
        reader: SysmonEventReader | None = None
        cursor: int | None = None
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                self._stop_event.wait(self.poll_interval)
                continue
            try:
                if reader is None:
                    reader = self.reader_factory()
                if cursor is None:
                    # 설치 직후 전체 과거 로그를 재분석하면 시작이 지연되므로 현재
                    # 마지막 레코드부터 새로 발생하는 이벤트만 실시간 수집한다.
                    cursor = reader.latest_record_id()
                    self._publish_status("running", "실시간 Sysmon 수집 중")
                for record in reader.read_after(cursor):
                    self._submit(record)
                    # 저장·분석이 성공한 뒤에만 커서를 전진시켜 실패 이벤트가
                    # 다음 재시도에서 조용히 유실되지 않도록 한다.
                    cursor = max(cursor, record.record_id)
                self._stop_event.wait(self.poll_interval)
            except Exception as error:
                self.logger.warning("Sysmon collector retrying: %s", error)
                self._publish_status(
                    "error",
                    self._friendly_error(error),
                    last_error=type(error).__name__,
                )
                reader = None
                self._stop_event.wait(min(5.0, self.poll_interval * 5))

    def _submit(self, record: SysmonLogRecord) -> None:
        event = self._parser.parse(record.xml)
        incident_id = self._incident_id(event)
        batch = NormalizedEventBatch(
            batch_id=f"sysmon-batch-{record.record_id}",
            incident_id=incident_id,
            collector_id="sysmon-local",
            received_at=datetime.now(UTC),
            events=[event],
        )
        self.sink.submit(batch)
        self._processed_count += 1
        self._publish_status(
            "running",
            "실시간 Sysmon 수집 중",
            last_event_at=event.timestamp.isoformat(),
        )

    @staticmethod
    def _incident_id(event: SecurityEvent) -> str:
        process_guid = getattr(event, "process_guid", None)
        correlation_key = process_guid or event.event_id
        safe_key = re.sub(r"[^a-zA-Z0-9]+", "-", correlation_key).strip("-").lower()
        return f"sysmon-{event.host_id.lower()}-{safe_key}"

    def _publish_status(
        self,
        state: str,
        label: str,
        *,
        last_event_at: str | None = None,
        last_error: str | None = None,
    ) -> None:
        if not self.status_callback:
            return
        status: dict[str, object] = {
            "state": state,
            "label": label,
            "source": "Sysmon",
            "sources": ["Sysmon"] if state in {"starting", "running", "paused"} else [],
            "processed_events": self._processed_count,
        }
        if last_event_at:
            status["last_event_at"] = last_event_at
        if last_error:
            status["last_error"] = last_error
        self.status_callback(status)

    @staticmethod
    def _friendly_error(error: Exception) -> str:
        error_code = getattr(error, "winerror", None)
        if error_code == 5:
            return "Sysmon 로그 읽기 권한 부족"
        if error_code in {2, 15007}:
            return "Sysmon 로그를 찾을 수 없음"
        if isinstance(error, ModuleNotFoundError):
            return "Windows 이벤트 로그 모듈 누락"
        return "Sysmon 수집 오류 · 자동 재시도 중"
