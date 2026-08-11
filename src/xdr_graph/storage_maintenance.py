from __future__ import annotations

import os
import gzip
import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel


class StorageHealth(BaseModel):
    database_bytes: int
    free_disk_bytes: int
    page_count: int
    free_pages: int
    integrity_ok: bool
    schema_version: int
    retention_days: int
    estimated_days_remaining: int | None = None


class BackupInfo(BaseModel):
    file_name: str
    size_bytes: int
    created_at: datetime
    integrity_ok: bool


class ArchiveInfo(BaseModel):
    file_name: str
    incidents: int
    events: int
    batches: int
    size_bytes: int
    sha256: str


class RecoveryStatus(BaseModel):
    pending_restore: bool
    rollback_available: bool


@dataclass(frozen=True)
class Migration:
    version: int
    statements: tuple[str, ...]


class DatabaseLifecycleManager:
    """Bound backups, integrity checks and transactional migrations to one data root."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        backup_root: str | Path,
        archive_root: str | Path | None = None,
        retention_days: int = 30,
    ) -> None:
        self.database_path = Path(database_path).resolve()
        self.backup_root = Path(backup_root).resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.archive_root = Path(archive_root or self.backup_root.parent / "archives").resolve()
        self.archive_root.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.pending_restore_path = self.database_path.with_suffix(self.database_path.suffix + ".restore-pending")
        self.rollback_path = self.database_path.with_suffix(self.database_path.suffix + ".rollback")

    @staticmethod
    def _integrity_ok(path: Path) -> bool:
        try:
            with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as connection:
                return connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        except sqlite3.DatabaseError:
            return False

    def live_integrity_ok(self) -> bool:
        return not self.database_path.exists() or self._integrity_ok(self.database_path)

    def health(self, *, daily_growth_bytes: int | None = None) -> StorageHealth:
        with closing(sqlite3.connect(self.database_path)) as connection:
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            free_pages = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
            integrity_ok = connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            try:
                schema_version = int(connection.execute("SELECT value FROM storage_metadata WHERE key='schema_version'").fetchone()[0])
            except (sqlite3.DatabaseError, TypeError):
                schema_version = 1
        free_disk = shutil.disk_usage(self.database_path.parent).free
        estimated = free_disk // daily_growth_bytes if daily_growth_bytes and daily_growth_bytes > 0 else None
        return StorageHealth(
            database_bytes=page_count * page_size,
            free_disk_bytes=free_disk,
            page_count=page_count,
            free_pages=free_pages,
            integrity_ok=integrity_ok,
            schema_version=schema_version,
            retention_days=self.retention_days,
            estimated_days_remaining=estimated,
        )

    def query_plan(self, sql: str, parameters: tuple[object, ...] = ()) -> list[str]:
        if not sql.lstrip().upper().startswith("SELECT"):
            raise ValueError("query plan inspection only accepts SELECT")
        with closing(sqlite3.connect(self.database_path)) as connection:
            return [str(row[3]) for row in connection.execute(f"EXPLAIN QUERY PLAN {sql}", parameters)]

    def backup(self) -> Path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = self.backup_root / f"weavexdr-{stamp}.db"
        temporary = self.backup_root / f".{destination.name}.tmp"
        if temporary.exists():
            temporary.unlink()
        # sqlite3.Connection의 context manager는 commit만 수행하고 handle은 닫지 않는다.
        # Windows에서는 열린 handle 때문에 원자적 rename이 실패하므로 명시적으로 닫는다.
        with closing(sqlite3.connect(self.database_path)) as source:
            with closing(sqlite3.connect(temporary)) as target:
                source.backup(target)
        if not self._integrity_ok(temporary):
            temporary.unlink(missing_ok=True)
            raise RuntimeError("database backup failed integrity verification")
        os.replace(temporary, destination)
        return destination

    def list_backups(self) -> list[BackupInfo]:
        backups: list[BackupInfo] = []
        for path in sorted(self.backup_root.glob("weavexdr-*.db"), key=lambda item: item.stat().st_mtime, reverse=True):
            stat = path.stat()
            backups.append(
                BackupInfo(
                    file_name=path.name,
                    size_bytes=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC),
                    integrity_ok=self._integrity_ok(path),
                )
            )
        return backups

    def stage_restore(self, file_name: str, *, confirmed: bool) -> RecoveryStatus:
        if not confirmed:
            raise PermissionError("database restore requires explicit confirmation")
        if Path(file_name).name != file_name or not file_name.endswith(".db"):
            raise ValueError("backup file name is invalid")
        source = (self.backup_root / file_name).resolve(strict=True)
        if source.parent != self.backup_root or not self._integrity_ok(source):
            raise ValueError("backup integrity check failed")
        temporary = self.pending_restore_path.with_suffix(self.pending_restore_path.suffix + ".tmp")
        shutil.copy2(source, temporary)
        if not self._integrity_ok(temporary):
            temporary.unlink(missing_ok=True)
            raise ValueError("staged restore integrity check failed")
        os.replace(temporary, self.pending_restore_path)
        return self.recovery_status()

    def apply_pending_restore(self) -> bool:
        """Apply a verified restore before SQLiteEventStore opens the live database."""
        if not self.pending_restore_path.exists():
            return False
        if not self._integrity_ok(self.pending_restore_path):
            self.pending_restore_path.unlink(missing_ok=True)
            raise RuntimeError("pending database restore failed integrity verification")
        if self.database_path.exists():
            shutil.copy2(self.database_path, self.rollback_path)
        os.replace(self.pending_restore_path, self.database_path)
        return True

    def recovery_status(self) -> RecoveryStatus:
        return RecoveryStatus(
            pending_restore=self.pending_restore_path.exists(),
            rollback_available=self.rollback_path.exists() and self._integrity_ok(self.rollback_path),
        )

    def archive_expired(self, *, now: datetime | None = None) -> ArchiveInfo:
        reference = (now or datetime.now(UTC)).astimezone(UTC)
        cutoff = (reference - timedelta(days=self.retention_days)).isoformat()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            incidents = [dict(row) for row in connection.execute("SELECT * FROM incidents WHERE updated_at < ?", (cutoff,))]
            incident_ids = [row["incident_id"] for row in incidents]
            if incident_ids:
                placeholders = ",".join("?" for _ in incident_ids)
                events = [dict(row) for row in connection.execute(f"SELECT * FROM events WHERE incident_id IN ({placeholders})", incident_ids)]
                batches = [dict(row) for row in connection.execute(f"SELECT * FROM batches WHERE incident_id IN ({placeholders})", incident_ids)]
            else:
                events, batches = [], []
        stamp = reference.strftime("%Y%m%dT%H%M%SZ")
        destination = self.archive_root / f"weavexdr-archive-{stamp}.json.gz"
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        payload = {
            "format": "weavexdr-archive-v1",
            "created_at": reference.isoformat(),
            "cutoff": cutoff,
            "incidents": incidents,
            "events": events,
            "batches": batches,
        }
        with gzip.open(temporary, "wt", encoding="utf-8") as archive:
            json.dump(payload, archive, ensure_ascii=False, separators=(",", ":"))
        os.replace(temporary, destination)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        return ArchiveInfo(
            file_name=destination.name,
            incidents=len(incidents),
            events=len(events),
            batches=len(batches),
            size_bytes=destination.stat().st_size,
            sha256=digest,
        )

    def restore(self, backup_path: str | Path, *, confirmed: bool) -> Path:
        if not confirmed:
            raise PermissionError("database restore requires explicit confirmation")
        source = Path(backup_path).resolve(strict=True)
        if source.parent != self.backup_root or source.suffix.lower() != ".db":
            raise ValueError("backup must be a direct child of the configured backup directory")
        if not self._integrity_ok(source):
            raise ValueError("backup integrity check failed")
        rollback = self.rollback_path
        temporary = self.database_path.with_suffix(self.database_path.suffix + ".restore.tmp")
        shutil.copy2(source, temporary)
        if not self._integrity_ok(temporary):
            temporary.unlink(missing_ok=True)
            raise ValueError("restored copy integrity check failed")
        if self.database_path.exists():
            shutil.copy2(self.database_path, rollback)
        os.replace(temporary, self.database_path)
        return rollback

    def apply_migrations(self, migrations: list[Migration]) -> int:
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS storage_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            row = connection.execute("SELECT value FROM storage_metadata WHERE key='schema_version'").fetchone()
            current = int(row[0]) if row else 1
            for migration in sorted(migrations, key=lambda item: item.version):
                if migration.version <= current:
                    continue
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    for statement in migration.statements:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT OR REPLACE INTO storage_metadata(key,value) VALUES('schema_version',?)",
                        (str(migration.version),),
                    )
                    connection.commit()
                    current = migration.version
                except Exception:
                    connection.rollback()
                    raise
            return current
