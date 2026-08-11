from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from xdr_graph.storage_maintenance import DatabaseLifecycleManager


@dataclass(frozen=True)
class StartupRecoveryReport:
    unclean_shutdown_detected: bool = False
    database_integrity_ok: bool = True
    recovery_action: str = "none"
    recovery_backup: str | None = None


class RuntimeRecoveryManager:
    """Detect incomplete shutdowns before DB open and preserve a verified recovery point."""

    def __init__(self, data_root: str | Path, storage: DatabaseLifecycleManager) -> None:
        self.data_root = Path(data_root)
        self.storage = storage
        self.marker_path = self.data_root / "runtime-active.json"

    def begin(self) -> StartupRecoveryReport:
        unclean = self.marker_path.exists()
        integrity_ok = True
        action = "none"
        recovery_backup: str | None = None
        if unclean and self.storage.database_path.exists():
            integrity_ok = self.storage.live_integrity_ok()
            if integrity_ok:
                recovery_backup = self.storage.backup().name
                action = "verified_backup_created"
            elif self.storage.recovery_status().rollback_available:
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                corrupt_copy = self.storage.database_path.with_suffix(f".corrupt-{stamp}.db")
                shutil.copy2(self.storage.database_path, corrupt_copy)
                shutil.copy2(self.storage.rollback_path, self.storage.database_path)
                integrity_ok = self.storage.live_integrity_ok()
                action = "verified_rollback_applied"
            else:
                raise RuntimeError("비정상 종료 후 데이터베이스 무결성 검사에 실패했고 검증된 복구본이 없습니다.")
        temporary = self.marker_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"pid": os.getpid(), "started_at": datetime.now(UTC).isoformat()}),
            encoding="utf-8",
        )
        os.replace(temporary, self.marker_path)
        return StartupRecoveryReport(unclean, integrity_ok, action, recovery_backup)

    def complete(self) -> None:
        self.marker_path.unlink(missing_ok=True)
