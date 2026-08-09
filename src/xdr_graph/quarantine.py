from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import uuid4

from pydantic import BaseModel


class QuarantineItem(BaseModel):
    item_id: str
    command_id: str
    original_path: str
    quarantine_path: str
    sha256: str
    status: str
    quarantined_at: datetime
    restored_at: datetime | None = None


class QuarantineStore:
    """파일을 삭제하지 않고 제한된 저장소로 이동하며 복원 정보를 보존한다."""

    def __init__(
        self,
        root_path: str | Path = "data/quarantine",
        database_path: str | Path = "data/xdr.db",
    ) -> None:
        self.root_path = Path(root_path).resolve()
        self.root_path.mkdir(parents=True, exist_ok=True)
        database_name = str(database_path)
        if database_name != ":memory:":
            Path(database_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(database_name, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine_items (
                    item_id TEXT PRIMARY KEY,
                    command_id TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    restored_at TEXT
                )
                """
            )

    def quarantine(
        self, file_path: str | Path, *, expected_sha256: str, command_id: str
    ) -> QuarantineItem:
        original_path = Path(file_path).resolve(strict=True)
        if not original_path.is_file() or original_path.is_symlink():
            raise ValueError("quarantine target must be a regular non-symlink file")
        actual_hash = self._sha256(original_path)
        if actual_hash.lower() != expected_sha256.lower():
            raise ValueError("file SHA-256 changed before quarantine")

        item_id = f"quarantine-{uuid4()}"
        quarantine_path = self.root_path / f"{item_id}.bin"
        quarantined_at = datetime.now(timezone.utc)
        try:
            # 원본을 삭제하지 않고 전용 폴더로 이동한다. shutil.move는 다른 볼륨도 지원한다.
            shutil.move(str(original_path), str(quarantine_path))
            os.chmod(quarantine_path, 0o600)
            item = QuarantineItem(
                item_id=item_id,
                command_id=command_id,
                original_path=str(original_path),
                quarantine_path=str(quarantine_path),
                sha256=actual_hash,
                status="quarantined",
                quarantined_at=quarantined_at,
            )
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO quarantine_items (
                        item_id, command_id, original_path, quarantine_path,
                        sha256, status, quarantined_at, restored_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        item.item_id,
                        item.command_id,
                        item.original_path,
                        item.quarantine_path,
                        item.sha256,
                        item.status,
                        item.quarantined_at.isoformat(),
                    ),
                )
            return item
        except Exception:
            # 메타데이터 기록 등 이동 후 단계가 실패하면 가능한 경우 원래 위치로 되돌린다.
            if quarantine_path.exists() and not original_path.exists():
                shutil.move(str(quarantine_path), str(original_path))
            raise

    def restore(self, item_id: str) -> QuarantineItem:
        item = self.get(item_id)
        if item.status != "quarantined":
            raise ValueError(f"quarantine item is already {item.status}")
        quarantine_path = Path(item.quarantine_path)
        original_path = Path(item.original_path)
        if not quarantine_path.is_file():
            raise FileNotFoundError("quarantined file is missing")
        if self._sha256(quarantine_path) != item.sha256:
            raise ValueError("quarantined file integrity check failed")
        if original_path.exists():
            raise FileExistsError("original path is occupied; refusing to overwrite")

        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(original_path))
        restored_at = datetime.now(timezone.utc)
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE quarantine_items
                SET status = 'restored', restored_at = ?
                WHERE item_id = ?
                """,
                (restored_at.isoformat(), item_id),
            )
        return item.model_copy(update={"status": "restored", "restored_at": restored_at})

    def get(self, item_id: str) -> QuarantineItem:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM quarantine_items WHERE item_id = ?", (item_id,)
            ).fetchone()
        if row is None:
            raise KeyError("quarantine item was not found")
        return QuarantineItem(
            item_id=row["item_id"],
            command_id=row["command_id"],
            original_path=row["original_path"],
            quarantine_path=row["quarantine_path"],
            sha256=row["sha256"],
            status=row["status"],
            quarantined_at=datetime.fromisoformat(row["quarantined_at"]),
            restored_at=(
                datetime.fromisoformat(row["restored_at"]) if row["restored_at"] else None
            ),
        )

    @staticmethod
    def _sha256(file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "QuarantineStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
