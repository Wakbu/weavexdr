from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
import time
from typing import Iterable


@dataclass(frozen=True)
class IntegrityStatus:
    state: str
    checked_at: str
    baseline_files: int
    changed: list[str]
    missing: list[str]
    added: list[str]


class SelfProtectionMonitor:
    """실행 파일·정책·탐지 콘텐츠가 기준 해시에서 달라졌는지 감시한다."""

    def __init__(self, baseline_path: str | Path, protected_paths: Iterable[str | Path]) -> None:
        self.baseline_path = Path(baseline_path).resolve()
        self.protected_paths = tuple(Path(value).resolve() for value in protected_paths)
        self._lock = RLock()
        self._cached_status: IntegrityStatus | None = None
        self._cache_checked_at = 0.0
        self._cache_fingerprint: tuple[tuple[str, int, int], ...] = ()

    def initialize(self) -> IntegrityStatus:
        with self._lock:
            current = self._snapshot()
            if not self.baseline_path.exists():
                self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
                self.baseline_path.write_text(json.dumps({"version": 1, "files": current}, indent=2), encoding="utf-8")
            # 시작 직전에 계산한 해시를 다시 읽지 않는다. 단일 EXE는 수십 MB라
            # 동일 파일을 연속 두 번 해시하면 첫 화면 표시가 불필요하게 늦어진다.
            status = self._compare(current)
            self._cached_status, self._cache_checked_at = status, time.monotonic()
            self._cache_fingerprint = self._fingerprint()
            return status

    def verify(self, *, force: bool = False) -> IntegrityStatus:
        with self._lock:
            # /status와 /security/integrity가 동시에 호출돼도 15초 안에는 시작 시
            # 검증 결과를 공유한다. 이후 주기 검증에서는 다시 실제 파일을 읽는다.
            fingerprint = self._fingerprint()
            if not force and self._cached_status and fingerprint == self._cache_fingerprint and time.monotonic() - self._cache_checked_at < 15:
                return self._cached_status
            if not self.baseline_path.is_file():
                return IntegrityStatus("not_initialized", datetime.now(UTC).isoformat(), 0, [], [], [])
            status = self._compare(self._snapshot())
            self._cached_status, self._cache_checked_at = status, time.monotonic()
            self._cache_fingerprint = fingerprint
            return status

    def _compare(self, current: dict[str, str]) -> IntegrityStatus:
        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8")).get("files", {})
        changed = sorted(name for name in baseline.keys() & current.keys() if baseline[name] != current[name])
        missing = sorted(baseline.keys() - current.keys())
        added = sorted(current.keys() - baseline.keys())
        state = "healthy" if not (changed or missing or added) else "tamper_detected"
        return IntegrityStatus(state, datetime.now(UTC).isoformat(), len(baseline), changed, missing, added)

    def approve_current(self) -> IntegrityStatus:
        """검증된 업데이트 직후에만 호출해 새 설치 상태를 기준으로 승격한다."""
        with self._lock:
            current = self._snapshot()
            temporary = self.baseline_path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"version": 1, "files": current}, indent=2), encoding="utf-8")
            temporary.replace(self.baseline_path)
            self._cached_status = None
            return self.verify(force=True)

    def _snapshot(self) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        for root in self.protected_paths:
            candidates = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file()) if root.is_dir() else []
            for path in candidates:
                # DB·로그처럼 정상 실행 중 계속 변하는 파일은 보호 기준에서 제외하고
                # 실행 파일과 정적 정책·규칙만 대상으로 삼는다.
                if path.suffix.casefold() not in {".exe", ".json", ".xml", ".yar", ".yara", ".py", ".html", ".svg"}:
                    continue
                key = str(path)
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                snapshot[key] = digest.hexdigest()
        return snapshot

    def _fingerprint(self) -> tuple[tuple[str, int, int], ...]:
        """내용 해시 전에 크기·수정 시각으로 캐시가 유효한지만 빠르게 본다."""
        values: list[tuple[str, int, int]] = []
        for root in self.protected_paths:
            candidates = [root] if root.is_file() else (path for path in root.rglob("*") if path.is_file()) if root.is_dir() else []
            for path in candidates:
                if path.suffix.casefold() in {".exe", ".json", ".xml", ".yar", ".yara", ".py", ".html", ".svg"}:
                    stat = path.stat()
                    values.append((str(path), stat.st_size, stat.st_mtime_ns))
        return tuple(sorted(values))

    @staticmethod
    def as_payload(status: IntegrityStatus) -> dict[str, object]:
        return asdict(status)
