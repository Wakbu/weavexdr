"""SQLite 기반 사건·이벤트 저장소와 메모리 수집 버퍼를 제공한다.

모든 동적 값은 SQL 매개변수로 전달하고, 정렬·WHERE 조각은 코드에 정의된 허용 목록만
조합한다. 연결은 재진입 잠금으로 보호하며 쓰기는 connection context의 트랜잭션 안에서
완료한다. 대량 목록은 서버 페이지 제한을 강제해 UI가 DB 전체를 메모리에 올리지 않는다.
"""

from __future__ import annotations

import sqlite3
import json
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Callable, Iterable, Literal

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


@dataclass(frozen=True)
class BufferStatus:
    queued_events: int
    capacity: int
    pressure_ratio: float
    state: str
    dropped_events: int = 0
    sampled_batches: int = 0


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
                CREATE INDEX IF NOT EXISTS idx_events_type_host_time
                    ON events (event_type, host_id, event_time);

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
                CREATE INDEX IF NOT EXISTS idx_incidents_verdict_risk_time
                    ON incidents (verdict, risk_score DESC, updated_at DESC);
                CREATE TABLE IF NOT EXISTS storage_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO storage_metadata(key,value) VALUES('schema_version','1');
                CREATE TABLE IF NOT EXISTS incident_management (
                    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'new',
                    note TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    bookmarked INTEGER NOT NULL DEFAULT 0,
                    checklist_json TEXT NOT NULL DEFAULT '[]',
                    custom_title TEXT,
                    close_reason TEXT,
                    is_demo INTEGER NOT NULL DEFAULT 0,
                    archived_at TEXT,
                    graph_config_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incident_management_status
                    ON incident_management (status, bookmarked, updated_at);
                CREATE TABLE IF NOT EXISTS saved_searches (
                    search_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    filters_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS custom_detections (
                    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL UNIQUE REFERENCES saved_searches(search_id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'shadow',
                    last_run_at TEXT,
                    next_run_at TEXT,
                    last_match_count INTEGER NOT NULL DEFAULT 0,
                    estimated_daily_matches REAL NOT NULL DEFAULT 0,
                    sample_incident_ids_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_custom_detections_schedule
                    ON custom_detections (state, next_run_at);
                CREATE TABLE IF NOT EXISTS incident_feedback_candidates (
                    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    label TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rule_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
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
    def _default_management(incident_id: str) -> dict[str, object]:
        return {
            "status": "new",
            "note": "",
            "tags": [],
            "bookmarked": False,
            "checklist": [],
            "custom_title": None,
            "close_reason": None,
            "is_demo": incident_id.startswith("demo-incident-"),
            "archived_at": None,
            "graph_config": {},
        }

    @classmethod
    def _management_from_row(cls, incident_id: str, row: sqlite3.Row | None) -> dict[str, object]:
        if row is None or row["management_status"] is None:
            return cls._default_management(incident_id)
        return {
            "status": row["management_status"],
            "note": row["management_note"],
            "tags": json.loads(row["management_tags"]),
            "bookmarked": bool(row["management_bookmarked"]),
            "checklist": json.loads(row["management_checklist"]),
            "custom_title": row["management_title"],
            "close_reason": row["management_close_reason"],
            "is_demo": bool(row["management_is_demo"]),
            "archived_at": row["management_archived_at"],
            "graph_config": json.loads(row["management_graph_config"] or "{}"),
        }

    def load_incident_view(self, incident_id: str) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT i.report_json,
                    m.status AS management_status, m.note AS management_note,
                    m.tags_json AS management_tags, m.bookmarked AS management_bookmarked,
                    m.checklist_json AS management_checklist, m.custom_title AS management_title,
                    m.close_reason AS management_close_reason, m.is_demo AS management_is_demo,
                    m.archived_at AS management_archived_at, m.graph_config_json AS management_graph_config
                FROM incidents i LEFT JOIN incident_management m USING (incident_id)
                WHERE i.incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        report = json.loads(row["report_json"])
        report["management"] = self._management_from_row(incident_id, row)
        return report

    def update_incident_management(self, incident_id: str, changes: dict[str, object]) -> dict[str, object]:
        allowed = {"status", "note", "tags", "bookmarked", "checklist", "custom_title", "close_reason", "archived_at", "graph_config"}
        if unknown := set(changes) - allowed:
            raise ValueError(f"unsupported incident fields: {sorted(unknown)}")
        current = self.load_incident_view(incident_id)
        if current is None:
            raise KeyError(incident_id)
        management = dict(current["management"])
        management.update(changes)
        if management["status"] not in {"new", "investigating", "on_hold", "resolved", "false_positive"}:
            raise ValueError("invalid incident status")
        tags = [str(value).strip() for value in management["tags"] if str(value).strip()][:20]
        checklist = [str(value).strip() for value in management["checklist"] if str(value).strip()][:30]
        now = self._utc_now().isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO incident_management (
                    incident_id, status, note, tags_json, bookmarked, checklist_json,
                    custom_title, close_reason, is_demo, archived_at, graph_config_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status=excluded.status, note=excluded.note, tags_json=excluded.tags_json,
                    bookmarked=excluded.bookmarked, checklist_json=excluded.checklist_json,
                    custom_title=excluded.custom_title, close_reason=excluded.close_reason,
                    archived_at=excluded.archived_at, graph_config_json=excluded.graph_config_json,
                    updated_at=excluded.updated_at
                """,
                (
                    incident_id, management["status"], str(management["note"])[:10000],
                    json.dumps(tags, ensure_ascii=False), int(bool(management["bookmarked"])),
                    json.dumps(checklist, ensure_ascii=False), management["custom_title"],
                    management["close_reason"], int(bool(management["is_demo"])),
                    management["archived_at"], json.dumps(management["graph_config"], ensure_ascii=False), now,
                ),
            )
            if management["status"] == "false_positive" and management["close_reason"]:
                # 오탐 한 건으로 규칙을 바로 끄지 않고 기존 검토 절차에 넘길 후보로만 남긴다.
                rule_ids = [finding["rule_id"] for finding in current.get("findings", [])]
                self._connection.execute(
                    """
                    INSERT INTO incident_feedback_candidates(incident_id,label,reason,rule_ids_json,created_at)
                    VALUES (?, 'false_positive', ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET reason=excluded.reason,
                        rule_ids_json=excluded.rule_ids_json, created_at=excluded.created_at
                    """,
                    (incident_id, management["close_reason"], json.dumps(rule_ids), now),
                )
        updated = self.load_incident_view(incident_id)
        assert updated is not None
        return updated

    def delete_demo_incidents(self) -> int:
        with self._lock, self._connection:
            ids = [row[0] for row in self._connection.execute(
                "SELECT incident_id FROM incidents WHERE incident_id LIKE 'demo-incident-%'"
            ).fetchall()]
            if not ids:
                return 0
            placeholders = ",".join("?" for _ in ids)
            self._connection.execute(f"DELETE FROM events WHERE incident_id IN ({placeholders})", ids)
            self._connection.execute(f"DELETE FROM batches WHERE incident_id IN ({placeholders})", ids)
            self._connection.execute(f"DELETE FROM incidents WHERE incident_id IN ({placeholders})", ids)
        return len(ids)

    def delete_incident(self, incident_id: str) -> bool:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM events WHERE incident_id = ?", (incident_id,))
            self._connection.execute("DELETE FROM batches WHERE incident_id = ?", (incident_id,))
            cursor = self._connection.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
        return cursor.rowcount > 0

    def save_search(self, name: str, filters: dict[str, object]) -> dict[str, object]:
        now = self._utc_now().isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO saved_searches(name, filters_json, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET filters_json=excluded.filters_json",
                (name.strip(), json.dumps(filters, ensure_ascii=False), now),
            )
            row = self._connection.execute(
                "SELECT search_id FROM saved_searches WHERE name = ?", (name.strip(),)
            ).fetchone()
        return {"search_id": row["search_id"], "name": name.strip(), "filters": filters}

    def list_saved_searches(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT search_id, name, filters_json FROM saved_searches ORDER BY name"
            ).fetchall()
        return [{"search_id": row["search_id"], "name": row["name"], "filters": json.loads(row["filters_json"])} for row in rows]

    def delete_saved_search(self, search_id: int) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM saved_searches WHERE search_id = ?", (search_id,))
        return cursor.rowcount > 0

    def get_saved_search(self, search_id: int) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT search_id, name, filters_json FROM saved_searches WHERE search_id = ?",
                (search_id,),
            ).fetchone()
        return None if row is None else {
            "search_id": row["search_id"], "name": row["name"],
            "filters": json.loads(row["filters_json"]),
        }

    def save_custom_detection(self, search_id: int, name: str, interval_minutes: int) -> dict[str, object]:
        """저장 헌팅을 먼저 shadow 상태로 등록해 검증 없는 자동 판정을 막는다."""
        if interval_minutes not in {15, 30, 60, 180, 360, 720, 1440}:
            raise ValueError("invalid custom detection interval")
        now = self._utc_now()
        next_run = now + timedelta(minutes=interval_minutes)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO custom_detections(search_id,name,interval_minutes,state,next_run_at,updated_at) "
                "VALUES (?,?,?,'shadow',?,?) ON CONFLICT(search_id) DO UPDATE SET "
                "name=excluded.name, interval_minutes=excluded.interval_minutes, "
                "state='shadow', next_run_at=excluded.next_run_at, updated_at=excluded.updated_at",
                (search_id, name.strip(), interval_minutes, next_run.isoformat(), now.isoformat()),
            )
        return self.get_custom_detection_by_search(search_id) or {}

    @staticmethod
    def _custom_detection_from_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "detection_id": row["detection_id"], "search_id": row["search_id"],
            "name": row["name"], "interval_minutes": row["interval_minutes"],
            "state": row["state"], "last_run_at": row["last_run_at"],
            "next_run_at": row["next_run_at"], "last_match_count": row["last_match_count"],
            "estimated_daily_matches": row["estimated_daily_matches"],
            "sample_incident_ids": json.loads(row["sample_incident_ids_json"]),
        }

    def get_custom_detection_by_search(self, search_id: int) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM custom_detections WHERE search_id = ?", (search_id,)
            ).fetchone()
        return None if row is None else self._custom_detection_from_row(row)

    def get_custom_detection(self, detection_id: int) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM custom_detections WHERE detection_id = ?", (detection_id,)
            ).fetchone()
        return None if row is None else self._custom_detection_from_row(row)

    def list_custom_detections(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM custom_detections ORDER BY state DESC, name"
            ).fetchall()
        return [self._custom_detection_from_row(row) for row in rows]

    def update_custom_detection_run(
        self, detection_id: int, *, match_count: int, estimated_daily_matches: float,
        sample_incident_ids: list[str],
    ) -> dict[str, object] | None:
        now = self._utc_now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT interval_minutes FROM custom_detections WHERE detection_id = ?", (detection_id,)
            ).fetchone()
            if row is None:
                return None
            next_run = now + timedelta(minutes=row["interval_minutes"])
            self._connection.execute(
                "UPDATE custom_detections SET last_run_at=?,next_run_at=?,last_match_count=?,"
                "estimated_daily_matches=?,sample_incident_ids_json=?,updated_at=? WHERE detection_id=?",
                (now.isoformat(), next_run.isoformat(), match_count, estimated_daily_matches,
                 json.dumps(sample_incident_ids[:100]), now.isoformat(), detection_id),
            )
        return self.get_custom_detection(detection_id)

    def set_custom_detection_state(self, detection_id: int, state: str) -> dict[str, object] | None:
        if state not in {"shadow", "active", "paused"}:
            raise ValueError("invalid custom detection state")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE custom_detections SET state=?,updated_at=? WHERE detection_id=?",
                (state, self._utc_now().isoformat(), detection_id),
            )
        return None if cursor.rowcount == 0 else self.get_custom_detection(detection_id)

    def list_feedback_candidates(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT incident_id,label,reason,rule_ids_json,created_at FROM incident_feedback_candidates ORDER BY created_at DESC"
            ).fetchall()
        return [{**dict(row), "rule_ids": json.loads(row["rule_ids_json"])} for row in rows]

    @staticmethod
    def _incident_filter_clause(
        verdict: str | None, query: str | None
    ) -> tuple[str, list[object]]:
        """허용된 사건 필터를 SQL 조각과 별도 바인딩 값으로 변환한다.

        반환 SQL에는 사용자 문자열이 포함되지 않는다. 호출자는 이 조각 뒤에 LIMIT을
        붙여 사용하며, 값 목록의 순서는 `?` 자리표시자 순서와 정확히 대응한다.
        """
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
        """최신 사건 원본을 제한된 페이지로 역직렬화한다.

        분석·내보내기처럼 전체 Pydantic 모델이 필요한 내부 경로용이다. 목록 화면은
        관리 메타데이터까지 한 JOIN으로 가져오는 `list_incident_views`를 사용한다.
        """
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

    def list_incident_views(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        verdict: str | None = None,
        query: str | None = None,
        status: str | None = None,
        min_risk: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        entity: str | None = None,
        sort: str = "updated_desc",
    ) -> list[dict[str, object]]:
        """사건과 관리 상태를 한 SQL 페이지로 조회한다.

        정렬 열은 사용자 문자열을 SQL에 넣지 않고 고정 딕셔너리에서 선택한다. 사건별
        추가 SELECT를 하지 않는 LEFT JOIN 구조라 페이지 크기 n에 대해 DB 왕복은 한 번이며,
        관리 행이 없는 기존 사건은 `_management_from_row`의 기본 상태로 보완한다.
        """
        if limit < 1 or limit > 500 or offset < 0:
            raise ValueError("invalid incident pagination")
        if verdict not in (None, "suspicious", "needs_review", "benign"):
            raise ValueError("invalid incident verdict filter")
        if status not in (None, "new", "investigating", "on_hold", "resolved", "false_positive"):
            raise ValueError("invalid incident status filter")
        if min_risk is not None and not 0 <= min_risk <= 100:
            raise ValueError("invalid minimum risk")
        order_by = {
            "updated_desc": "i.updated_at DESC, i.incident_id",
            "updated_asc": "i.updated_at ASC, i.incident_id",
            "risk_desc": "i.risk_score DESC, i.updated_at DESC",
            "risk_asc": "i.risk_score ASC, i.updated_at DESC",
        }.get(sort)
        if order_by is None:
            raise ValueError("invalid incident sort")
        clauses: list[str] = []
        parameters: list[object] = []
        if verdict:
            clauses.append("i.verdict = ?")
            parameters.append(verdict)
        if status:
            clauses.append("COALESCE(m.status, 'new') = ?")
            parameters.append(status)
        if min_risk is not None:
            clauses.append("i.risk_score >= ?")
            parameters.append(min_risk)
        if date_from:
            clauses.append("i.updated_at >= ?")
            parameters.append(date_from)
        if date_to:
            clauses.append("i.updated_at <= ?")
            parameters.append(date_to)
        for search_value in (query, entity):
            if search_value and search_value.strip():
                clauses.append("(i.incident_id LIKE ? OR i.report_json LIKE ? OR COALESCE(m.tags_json, '') LIKE ? OR COALESCE(m.custom_title, '') LIKE ?)")
                pattern = f"%{search_value.strip()}%"
                parameters.extend((pattern, pattern, pattern, pattern))
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT i.incident_id, i.report_json,
                    m.status AS management_status, m.note AS management_note,
                    m.tags_json AS management_tags, m.bookmarked AS management_bookmarked,
                    m.checklist_json AS management_checklist, m.custom_title AS management_title,
                    m.close_reason AS management_close_reason, m.is_demo AS management_is_demo,
                    m.archived_at AS management_archived_at, m.graph_config_json AS management_graph_config
                FROM incidents i LEFT JOIN incident_management m USING (incident_id)
                {where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?
                """,
                (*parameters, limit, offset),
            ).fetchall()
        views: list[dict[str, object]] = []
        for row in rows:
            report = json.loads(row["report_json"])
            report["management"] = self._management_from_row(row["incident_id"], row)
            views.append(report)
        return views

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

    def filtered_incident_count(
        self, *, verdict: str | None = None, query: str | None = None,
        status: str | None = None, min_risk: int | None = None,
        date_from: str | None = None, date_to: str | None = None,
        entity: str | None = None,
    ) -> int:
        """목록과 동일한 필터의 정확한 전체 건수를 DB에서 직접 계산한다.

        페이지 결과 길이를 전체 건수로 오인하지 않도록 별도 COUNT를 사용한다. 이 함수의
        조건은 `list_incident_views`와 같은 허용 목록을 유지해야 하며 결과 JSON은 읽지 않는다.
        """
        clauses: list[str] = []
        parameters: list[object] = []
        if verdict:
            if verdict not in {"suspicious", "needs_review", "benign"}:
                raise ValueError("invalid incident verdict filter")
            clauses.append("i.verdict = ?")
            parameters.append(verdict)
        if status:
            if status not in {"new", "investigating", "on_hold", "resolved", "false_positive"}:
                raise ValueError("invalid incident status filter")
            clauses.append("COALESCE(m.status, 'new') = ?")
            parameters.append(status)
        if min_risk is not None:
            if not 0 <= min_risk <= 100:
                raise ValueError("invalid minimum risk")
            clauses.append("i.risk_score >= ?")
            parameters.append(min_risk)
        if date_from:
            clauses.append("i.updated_at >= ?")
            parameters.append(date_from)
        if date_to:
            clauses.append("i.updated_at <= ?")
            parameters.append(date_to)
        for value in (query, entity):
            if value and value.strip():
                clauses.append("(i.incident_id LIKE ? OR i.report_json LIKE ? OR COALESCE(m.tags_json, '') LIKE ? OR COALESCE(m.custom_title, '') LIKE ?)")
                pattern = f"%{value.strip()}%"
                parameters.extend((pattern, pattern, pattern, pattern))
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return int(self._connection.execute(
                f"SELECT COUNT(*) FROM incidents i LEFT JOIN incident_management m USING (incident_id) {where_sql}", parameters
            ).fetchone()[0])

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

    def save_manual_incident(self, report: IncidentReport) -> None:
        """Persist a user merge/split result without fabricating raw batch records."""
        now = self._utc_now().isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO incidents(incident_id,last_batch_id,verdict,risk_score,report_json,updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET verdict=excluded.verdict,
                    risk_score=excluded.risk_score, report_json=excluded.report_json,
                    updated_at=excluded.updated_at
                """,
                (report.incident_id, "manual-management", report.verdict, report.risk_score, report.model_dump_json(), now),
            )

    def cleanup_expired(self, *, now: datetime | None = None) -> CleanupResult:
        """마지막 처리 시각이 보존 기간보다 오래된 데이터를 정리한다."""

        reference_time = now or self._utc_now()
        if reference_time.tzinfo is None or reference_time.utcoffset() is None:
            raise ValueError("cleanup time must include a timezone offset")
        cutoff = (reference_time.astimezone(timezone.utc) - timedelta(days=self.retention_days)).isoformat()

        with self._lock, self._connection:
            # 사용자가 해결·오탐으로 닫은 사건은 보존 기간이 되었다고
            # 바로 영구 삭제하지 않고 자동 보관한다. 영구 삭제는 별도 ID 확인을 요구한다.
            self._connection.execute(
                """
                UPDATE incident_management SET archived_at = COALESCE(archived_at, ?)
                WHERE status IN ('resolved', 'false_positive')
                  AND incident_id IN (SELECT incident_id FROM incidents WHERE updated_at < ?)
                """,
                (reference_time.astimezone(timezone.utc).isoformat(), cutoff),
            )
            event_cursor = self._connection.execute(
                "DELETE FROM events WHERE inserted_at < ?", (cutoff,)
            )
            batch_cursor = self._connection.execute(
                "DELETE FROM batches WHERE processed_at < ?", (cutoff,)
            )
            incident_cursor = self._connection.execute(
                """
                DELETE FROM incidents WHERE updated_at < ?
                  AND incident_id NOT IN (
                    SELECT incident_id FROM incident_management WHERE archived_at IS NOT NULL
                  )
                """,
                (cutoff,),
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

    SAMPLEABLE_EVENT_TYPES = {"dns_query", "firewall_connection"}

    def __init__(
        self,
        sink: EventBatchSink,
        *,
        capacity: int = 1000,
        overflow_policy: Literal["reject", "sample_low_priority"] = "reject",
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.sink = sink
        self.capacity = capacity
        self.overflow_policy = overflow_policy
        self._queued_events = 0
        self._batches: deque[NormalizedEventBatch] = deque()
        self._dropped_events = 0
        self._sampled_batches = 0

    @property
    def queued_event_count(self) -> int:
        return self._queued_events

    @property
    def queued_batch_count(self) -> int:
        return len(self._batches)

    def status(self) -> BufferStatus:
        ratio = self._queued_events / self.capacity
        state = "critical" if ratio >= .9 else "high" if ratio >= .7 else "normal"
        return BufferStatus(
            queued_events=self._queued_events,
            capacity=self.capacity,
            pressure_ratio=ratio,
            state=state,
            dropped_events=self._dropped_events,
            sampled_batches=self._sampled_batches,
        )

    def enqueue(self, batch: NormalizedEventBatch) -> None:
        """배치를 FIFO 버퍼에 추가하되 용량 초과를 조용히 숨기지 않는다.

        기본 정책은 명시적 `BufferFullError`다. 선택적 샘플링 정책도 DNS·네트워크처럼
        반복량이 큰 저우선 이벤트만 균등 간격으로 줄이며 고가치 이벤트는 전부 보존한다.
        """
        incoming_count = len(batch.events)
        if self._queued_events + incoming_count > self.capacity:
            if self.overflow_policy == "sample_low_priority":
                batch = self._sample_to_capacity(batch)
                incoming_count = len(batch.events)
            if self._queued_events + incoming_count <= self.capacity:
                self._batches.append(batch)
                self._queued_events += incoming_count
                return
            # 오래된 보안 이벤트를 조용히 버리면 탐지 공백이 생긴다. 호출자가
            # 재시도나 디스크 스풀을 선택할 수 있도록 명시적으로 실패시킨다.
            raise BufferFullError(
                f"event buffer capacity exceeded: {self._queued_events + incoming_count}/{self.capacity}"
            )
        self._batches.append(batch)
        self._queued_events += incoming_count

    def _sample_to_capacity(self, batch: NormalizedEventBatch) -> NormalizedEventBatch:
        """남은 슬롯에 저우선 이벤트를 시간 순서가 유지되는 균등 표본으로 축소한다."""
        available = self.capacity - self._queued_events
        if available < 1:
            return batch
        protected = [event for event in batch.events if event.event_type not in self.SAMPLEABLE_EVENT_TYPES]
        sampleable = [event for event in batch.events if event.event_type in self.SAMPLEABLE_EVENT_TYPES]
        # 프로세스·파일·Defender·계정 변경 같은 고가치 이벤트는 절대 샘플링하지 않는다.
        if len(protected) > available or not sampleable:
            return batch
        sample_slots = available - len(protected)
        if sample_slots >= len(sampleable):
            return batch
        # 무작위 표본은 실행마다 결과가 달라 조사 재현성이 떨어진다. 전체 범위를
        # sample_slots 구간으로 나눈 결정적 인덱스를 사용해 처음부터 끝까지 고르게 남긴다.
        sampled = [] if sample_slots == 0 else [
            sampleable[
                min(len(sampleable) - 1, int(index * len(sampleable) / sample_slots))
            ]
            for index in range(sample_slots)
        ]
        selected_ids = {event.event_id for event in [*protected, *sampled]}
        selected = [event for event in batch.events if event.event_id in selected_ids]
        dropped = len(batch.events) - len(selected)
        self._dropped_events += dropped
        self._sampled_batches += 1
        return batch.model_copy(update={"events": selected})

    def flush(self, *, max_batches: int | None = None) -> list[IngestionReceipt]:
        """앞쪽 배치부터 저장하고 성공이 확인된 항목만 큐에서 제거한다.

        sink가 예외를 내면 현재 배치를 머리에 둔 채 호출자에게 전파하므로 재시도할 수 있다.
        `max_batches`는 한 번의 flush가 수집 스레드를 장시간 독점하지 않게 하는 상한이다.
        """
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
