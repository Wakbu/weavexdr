from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel


class AuditRecord(BaseModel):
    record_id: str
    category: Literal["analysis", "response", "recovery", "system"]
    action: str
    status: str
    occurred_at: datetime
    details: dict[str, Any]
    previous_hash: str
    record_hash: str


class AuditLogger(Protocol):
    def record(
        self,
        category: Literal["analysis", "response", "recovery", "system"],
        action: str,
        status: str,
        details: dict[str, Any],
    ) -> AuditRecord: ...


class SQLiteAuditLog:
    """수정 여부를 확인할 수 있도록 이전 레코드 해시를 연결한 감사 로그."""

    def __init__(
        self,
        database_path: str | Path = "data/xdr.db",
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        database_name = str(database_path)
        if database_name != ":memory:":
            Path(database_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._connection = sqlite3.connect(database_name, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT UNIQUE NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )

    def record(self, category, action, status, details) -> AuditRecord:
        occurred_at = self._aware_now()
        details_json = json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock, self._connection:
            previous = self._connection.execute(
                "SELECT record_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["record_hash"] if previous else "0" * 64
            record_id = f"audit-{uuid4()}"
            hash_input = "|".join(
                [record_id, category, action, status, occurred_at.isoformat(), details_json, previous_hash]
            )
            record_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
            self._connection.execute(
                """
                INSERT INTO audit_log (
                    record_id, category, action, status, occurred_at,
                    details_json, previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    category,
                    action,
                    status,
                    occurred_at.isoformat(),
                    details_json,
                    previous_hash,
                    record_hash,
                ),
            )
        return AuditRecord(
            record_id=record_id,
            category=category,
            action=action,
            status=status,
            occurred_at=occurred_at,
            details=details,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )

    def list_records(self) -> list[AuditRecord]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM audit_log ORDER BY sequence"
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def verify_integrity(self) -> bool:
        previous_hash = "0" * 64
        for record in self.list_records():
            details_json = json.dumps(
                record.details, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            hash_input = "|".join(
                [
                    record.record_id,
                    record.category,
                    record.action,
                    record.status,
                    record.occurred_at.isoformat(),
                    details_json,
                    previous_hash,
                ]
            )
            if record.previous_hash != previous_hash or record.record_hash != hashlib.sha256(
                hash_input.encode("utf-8")
            ).hexdigest():
                return False
            previous_hash = record.record_hash
        return True

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            record_id=row["record_id"],
            category=row["category"],
            action=row["action"],
            status=row["status"],
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            details=json.loads(row["details_json"]),
            previous_hash=row["previous_hash"],
            record_hash=row["record_hash"],
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteAuditLog":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _aware_now(self) -> datetime:
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("audit clock must include a timezone offset")
        return current_time.astimezone(timezone.utc)
