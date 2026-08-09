from __future__ import annotations

import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Callable, Iterable

from pydantic import TypeAdapter

from xdr_graph.ingestion import (
    EventBatchSink,
    GraphIngestionService,
    IngestionReceipt,
    NormalizedEventBatch,
)
from xdr_graph.models import IncidentReport, SecurityEvent
from xdr_graph.events import IncidentPublisher


_event_adapter = TypeAdapter(SecurityEvent)


@dataclass(frozen=True)
class CleanupResult:
    """보존 기간이 지난 레코드를 종류별로 몇 건 지웠는지 나타낸다."""

    events: int
    batches: int
    incidents: int


@dataclass(frozen=True)
class StorageStats:
    """운영 상태 확인에 필요한 최소 저장 건수다."""

    events: int
    batches: int
    incidents: int


class SQLiteEventStore:
    """정규화 이벤트와 최신 사건 보고서를 SQLite에 영속화한다."""

    def __init__(
        self,
        database_path: str | Path = "data/xdr.db",
        *,
        retention_days: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if retention_days < 1:
            raise ValueError("retention_days must be at least 1")

        self.database_path = str(database_path)
        self.retention_days = retention_days
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._next_cleanup_at = self._utc_now()

        # 파일 DB라면 첫 실행에서도 바로 열리도록 상위 폴더만 만든다.
        # 테스트용 :memory: DB는 실제 경로가 아니므로 폴더 생성을 건너뛴다.
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)

        # 한 연결을 재사용해야 :memory: DB가 호출 사이에도 유지된다. lock은 향후
        # 수집 스레드가 늘어났을 때 같은 연결을 동시에 만지는 상황을 막는다.
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    inserted_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_incident_time
                    ON events (incident_id, event_time);

                CREATE TABLE IF NOT EXISTS batches (
                    batch_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    received_count INTEGER NOT NULL,
                    inserted_count INTEGER NOT NULL,
                    duplicate_count INTEGER NOT NULL,
                    processed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_batches_incident
                    ON batches (incident_id, processed_at);

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    last_batch_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    report_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def unseen_events(self, events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
        """이미 저장된 event_id를 제외하고 입력 순서를 유지해 반환한다."""

        candidates = list(events)
        if not candidates:
            return []

        placeholders = ",".join("?" for _ in candidates)
        with self._lock:
            rows = self._connection.execute(
                f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",
                [event.event_id for event in candidates],
            ).fetchall()
        stored_ids = {row["event_id"] for row in rows}
        return [event for event in candidates if event.event_id not in stored_ids]

    def load_incident_events(self, incident_id: str) -> list[SecurityEvent]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload_json FROM events
                WHERE incident_id = ?
                ORDER BY event_time, event_id
                """,
                (incident_id,),
            ).fetchall()
        return [_event_adapter.validate_json(row["payload_json"]) for row in rows]

    def load_incident_report(self, incident_id: str) -> IncidentReport | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT report_json FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return IncidentReport.model_validate_json(row["report_json"]) if row else None

    @staticmethod
    def _incident_filter_clause(
        verdict: str | None, query: str | None
    ) -> tuple[str, list[object]]:
        if verdict not in (None, "suspicious", "needs_review", "benign"):
            raise ValueError("invalid incident verdict filter")
        where_parts: list[str] = []
        parameters: list[object] = []
        if verdict:
            where_parts.append("verdict = ?")
            parameters.append(verdict)
        if query and query.strip():
            where_parts.append("(incident_id LIKE ? OR report_json LIKE ?)")
            search_pattern = f"%{query.strip()}%"
            parameters.extend((search_pattern, search_pattern))
        # 동적으로 조합하는 부분은 위의 고정 SQL 조각뿐이다. 사용자 검색어와
        # 판정 값은 항상 매개변수로 전달해 SQL 문장으로 해석되지 않게 한다.
        where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        return where_sql, parameters

    def list_incident_reports(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        verdict: str | None = None,
        query: str | None = None,
    ) -> list[IncidentReport]:
        if limit < 1 or limit > 500 or offset < 0:
            raise ValueError("invalid incident pagination")
        where_sql, parameters = self._incident_filter_clause(verdict, query)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT report_json FROM incidents
                {where_sql}
                ORDER BY updated_at DESC, incident_id
                LIMIT ? OFFSET ?
                """,
                (*parameters, limit, offset),
            ).fetchall()
        return [IncidentReport.model_validate_json(row["report_json"]) for row in rows]

    def incident_stats(
        self, *, verdict: str | None = None, query: str | None = None
    ) -> dict[str, object]:
        """전체 KPI와 현재 필터의 정확한 사건 수를 반환한다."""

        where_sql, parameters = self._incident_filter_clause(verdict, query)
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) AS count FROM incidents"
            ).fetchone()["count"]
            verdict_rows = self._connection.execute(
                "SELECT verdict, COUNT(*) AS count FROM incidents GROUP BY verdict"
            ).fetchall()
            filtered_total = self._connection.execute(
                f"SELECT COUNT(*) AS count FROM incidents {where_sql}", parameters
            ).fetchone()["count"]
            trend_rows = self._connection.execute(
                """
                SELECT substr(updated_at, 1, 10) AS day, COUNT(*) AS count
                FROM incidents
                WHERE updated_at >= datetime('now', '-7 days')
                GROUP BY substr(updated_at, 1, 10)
                """
            ).fetchall()
        verdict_counts = {"suspicious": 0, "needs_review": 0, "benign": 0}
        verdict_counts.update({row["verdict"]: row["count"] for row in verdict_rows})
        return {
            "total": total,
            "filtered_total": filtered_total,
            "verdicts": verdict_counts,
            "daily": {row["day"]: row["count"] for row in trend_rows},
        }

    def save_processed_batch(
        self,
        batch: NormalizedEventBatch,
        new_events: Iterable[SecurityEvent],
        report: IncidentReport,
    ) -> None:
        """그래프가 성공한 배치만 이벤트·배치·보고서 단위로 함께 커밋한다."""

        accepted_events = list(new_events)
        processed_at = self._utc_now().isoformat()
        duplicate_count = len(batch.events) - len(accepted_events)

        # 분석 도중 실패한 사건이 저장되어 정상 처리처럼 보이지 않도록 그래프 실행
        # 이후 이 메서드를 호출하고, 세 종류의 기록은 하나의 트랜잭션으로 커밋한다.
        with self._lock, self._connection:
            self._connection.executemany(
                """
                INSERT OR IGNORE INTO events (
                    event_id, incident_id, batch_id, event_type, event_time,
                    host_id, source, payload_json, inserted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        event.event_id,
                        batch.incident_id,
                        batch.batch_id,
                        event.event_type,
                        event.timestamp.astimezone(timezone.utc).isoformat(),
                        event.host_id,
                        event.source,
                        event.model_dump_json(),
                        processed_at,
                    )
                    for event in accepted_events
                ],
            )
            self._connection.execute(
                """
                INSERT INTO batches (
                    batch_id, incident_id, collector_id, received_at,
                    received_count, inserted_count, duplicate_count, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(batch_id) DO NOTHING
                """,
                (
                    batch.batch_id,
                    batch.incident_id,
                    batch.collector_id,
                    batch.received_at.astimezone(timezone.utc).isoformat(),
                    len(batch.events),
                    len(accepted_events),
                    duplicate_count,
                    processed_at,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, last_batch_id, verdict, risk_score,
                    report_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    last_batch_id = excluded.last_batch_id,
                    verdict = excluded.verdict,
                    risk_score = excluded.risk_score,
                    report_json = excluded.report_json,
                    updated_at = excluded.updated_at
                """,
                (
                    batch.incident_id,
                    batch.batch_id,
                    report.verdict,
                    report.risk_score,
                    report.model_dump_json(),
                    processed_at,
                ),
            )

    def cleanup_expired(self, *, now: datetime | None = None) -> CleanupResult:
        """마지막 처리 시각이 보존 기간보다 오래된 데이터를 정리한다."""

        reference_time = now or self._utc_now()
        if reference_time.tzinfo is None or reference_time.utcoffset() is None:
            raise ValueError("cleanup time must include a timezone offset")
        cutoff = (reference_time.astimezone(timezone.utc) - timedelta(days=self.retention_days)).isoformat()

        with self._lock, self._connection:
            event_cursor = self._connection.execute(
                "DELETE FROM events WHERE inserted_at < ?", (cutoff,)
            )
            batch_cursor = self._connection.execute(
                "DELETE FROM batches WHERE processed_at < ?", (cutoff,)
            )
            incident_cursor = self._connection.execute(
                "DELETE FROM incidents WHERE updated_at < ?", (cutoff,)
            )
        return CleanupResult(
            events=event_cursor.rowcount,
            batches=batch_cursor.rowcount,
            incidents=incident_cursor.rowcount,
        )

    def cleanup_if_due(self) -> CleanupResult:
        """수집 경로에서 최대 한 시간에 한 번 만료 데이터를 자동 정리한다."""

        current_time = self._utc_now()
        if current_time < self._next_cleanup_at:
            return CleanupResult(events=0, batches=0, incidents=0)

        removed = self.cleanup_expired(now=current_time)
        # 배치마다 DELETE를 실행하면 수집 지연이 커질 수 있어 정리 주기를 제한한다.
        # 프로세스를 재시작하면 첫 배치에서 즉시 정리하므로 별도 스케줄러가 없어도 된다.
        self._next_cleanup_at = current_time + timedelta(hours=1)
        return removed

    def stats(self) -> StorageStats:
        with self._lock:
            counts = {
                table: self._connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                for table in ("events", "batches", "incidents")
            }
        return StorageStats(**counts)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _utc_now(self) -> datetime:
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("storage clock must include a timezone offset")
        return current_time.astimezone(timezone.utc)

    def __enter__(self) -> "SQLiteEventStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class PersistentIngestionService:
    """배치 간 중복을 제거하고 사건 전체 증거를 다시 분석하는 입력 서비스다."""

    def __init__(
        self,
        store: SQLiteEventStore,
        graph_service: GraphIngestionService | None = None,
        event_publisher: IncidentPublisher | None = None,
    ) -> None:
        self.store = store
        self.graph_service = graph_service or GraphIngestionService()
        self.event_publisher = event_publisher

    def submit(self, batch: NormalizedEventBatch) -> IngestionReceipt:
        self.store.cleanup_if_due()
        fresh_events = self.store.unseen_events(batch.events)
        duplicate_count = len(batch.events) - len(fresh_events)

        if not fresh_events:
            # 동일 배치 재전송은 비싼 그래프 분석을 반복하지 않고 직전 보고서를 돌려준다.
            # 배치 처리 이력은 남겨 수집기가 정상적으로 전달했음을 확인할 수 있게 한다.
            previous_report = self.store.load_incident_report(batch.incident_id)
            if previous_report is None:
                raise RuntimeError("duplicate events exist without a stored incident report")
            self.store.save_processed_batch(batch, [], previous_report)
            return IngestionReceipt(
                batch_id=batch.batch_id,
                incident_id=batch.incident_id,
                accepted_event_count=0,
                duplicate_event_count=duplicate_count,
                analyzed=False,
                report=previous_report,
            )

        incident_events = self.store.load_incident_events(batch.incident_id)
        # 새 배치만 분석하면 앞선 프로세스 실행과 뒤늦게 도착한 파일·네트워크
        # 이벤트의 연관성을 놓친다. 사건에 누적된 증거를 시간순으로 다시 평가한다.
        all_events = sorted(
            [*incident_events, *fresh_events],
            key=lambda event: (event.timestamp, event.event_id),
        )
        analysis_batch = batch.model_copy(update={"events": all_events})
        graph_receipt = self.graph_service.submit(analysis_batch)
        self.store.save_processed_batch(batch, fresh_events, graph_receipt.report)
        if self.event_publisher:
            self.event_publisher.publish(graph_receipt.report)
        return IngestionReceipt(
            batch_id=batch.batch_id,
            incident_id=batch.incident_id,
            accepted_event_count=len(fresh_events),
            duplicate_event_count=duplicate_count,
            analyzed=True,
            report=graph_receipt.report,
        )


class BufferFullError(RuntimeError):
    """고정 용량 이벤트 버퍼에 더 넣을 공간이 없을 때 발생한다."""


class EventBuffer:
    """이벤트 수를 기준으로 용량을 제한하는 메모리 배치 큐다."""

    def __init__(self, sink: EventBatchSink, *, capacity: int = 1000) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.sink = sink
        self.capacity = capacity
        self._queued_events = 0
        self._batches: deque[NormalizedEventBatch] = deque()

    @property
    def queued_event_count(self) -> int:
        return self._queued_events

    @property
    def queued_batch_count(self) -> int:
        return len(self._batches)

    def enqueue(self, batch: NormalizedEventBatch) -> None:
        incoming_count = len(batch.events)
        if self._queued_events + incoming_count > self.capacity:
            # 오래된 보안 이벤트를 조용히 버리면 탐지 공백이 생긴다. 호출자가
            # 재시도나 디스크 스풀을 선택할 수 있도록 명시적으로 실패시킨다.
            raise BufferFullError(
                f"event buffer capacity exceeded: {self._queued_events + incoming_count}/{self.capacity}"
            )
        self._batches.append(batch)
        self._queued_events += incoming_count

    def flush(self, *, max_batches: int | None = None) -> list[IngestionReceipt]:
        if max_batches is not None and max_batches < 1:
            raise ValueError("max_batches must be at least 1")

        receipts: list[IngestionReceipt] = []
        while self._batches and (max_batches is None or len(receipts) < max_batches):
            next_batch = self._batches[0]
            # 저장 또는 분석 실패 시 데이터가 유실되지 않도록 성공한 뒤에만 큐에서 뺀다.
            receipt = self.sink.submit(next_batch)
            self._batches.popleft()
            self._queued_events -= len(next_batch.events)
            receipts.append(receipt)
        return receipts
