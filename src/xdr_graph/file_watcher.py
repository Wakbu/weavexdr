from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Callable, Iterable
from uuid import uuid4

from xdr_graph.file_scanner import FileInspectionEngine, FileInspectionResult
from xdr_graph.models import FileCreateEvent


FileLister = Callable[[Path, bool], Iterable[Path]]


@dataclass(frozen=True)
class WatchedFileResult:
    """폴더에서 발견한 파일 이벤트와 정적 검사 결과를 함께 전달한다."""

    event: FileCreateEvent
    inspection: FileInspectionResult | None
    error: str | None = None


def default_watch_directories() -> tuple[Path, ...]:
    """개인 PC에서 신규 실행 파일이 자주 유입되는 기본 감시 위치다."""

    candidates = (Path.home() / "Downloads", Path(tempfile.gettempdir()))
    # 같은 경로가 중복되거나 존재하지 않는 경우를 제거해 불필요한 순회를 피한다.
    unique_paths: dict[str, Path] = {}
    for candidate in candidates:
        if candidate.is_dir():
            unique_paths[str(candidate.resolve()).lower()] = candidate.resolve()
    return tuple(unique_paths.values())


def _list_directory_files(root: Path, recursive: bool) -> Iterable[Path]:
    entries = root.rglob("*") if recursive else root.iterdir()
    # 링크를 따라가면 감시 범위 밖 파일까지 검사할 수 있으므로 명시적으로 제외한다.
    return (entry for entry in entries if not entry.is_symlink() and entry.is_file())


class DirectoryFileWatcher:
    """다운로드·임시 폴더의 안정된 신규 파일을 주기적으로 검사한다."""

    def __init__(
        self,
        engine: FileInspectionEngine,
        roots: Iterable[str | Path] | None = None,
        *,
        recursive: bool = False,
        file_lister: FileLister = _list_directory_files,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        configured_roots = tuple(Path(root).resolve() for root in (roots or default_watch_directories()))
        if not configured_roots:
            raise ValueError("at least one watch directory is required")
        if any(not root.is_dir() for root in configured_roots):
            raise ValueError("all watch roots must be existing directories")

        self.engine = engine
        self.roots = configured_roots
        self.recursive = recursive
        self._file_lister = file_lister
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._event_id_factory = event_id_factory or (lambda: f"watch-{uuid4()}")
        self._known_files = self._snapshot_paths()
        self._pending_files: dict[Path, tuple[int, int]] = {}

    def scan_once(self) -> list[WatchedFileResult]:
        """두 번 연속 크기와 수정 시각이 같은 신규 파일만 검사한다."""

        current_files = self._snapshot_paths()
        results: list[WatchedFileResult] = []
        for file_path in sorted(current_files - self._known_files, key=str):
            try:
                file_stat = file_path.stat()
            except OSError:
                continue
            current_state = (file_stat.st_size, file_stat.st_mtime_ns)
            if self._pending_files.get(file_path) != current_state:
                # 다운로드 도중의 불완전한 파일을 검사하지 않도록 다음 폴링까지 기다린다.
                self._pending_files[file_path] = current_state
                continue

            event = FileCreateEvent(
                event_id=self._event_id_factory(),
                event_type="file_create",
                timestamp=self._aware_now(),
                host_id=os.environ.get("COMPUTERNAME", "local-host"),
                source="windows_event_log",
                file_path=str(file_path),
            )
            try:
                inspection = self.engine.inspect(file_path, event_id=event.event_id)
                results.append(WatchedFileResult(event=event, inspection=inspection))
            except (OSError, ValueError) as error:
                # 접근 거부나 크기 제한도 감시 루프를 멈추지 않고 관측 결과로 전달한다.
                results.append(
                    WatchedFileResult(event=event, inspection=None, error=str(error))
                )
            self._known_files.add(file_path)
            self._pending_files.pop(file_path, None)

        for vanished_path in set(self._pending_files) - current_files:
            self._pending_files.pop(vanished_path, None)
        return results

    def watch(
        self,
        stop_event: Event,
        on_result: Callable[[WatchedFileResult], None],
        *,
        poll_interval: float = 2.0,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        while not stop_event.is_set():
            for result in self.scan_once():
                on_result(result)
            # Event.wait를 사용하면 종료 신호가 왔을 때 sleep보다 즉시 깨어날 수 있다.
            stop_event.wait(poll_interval)

    def _snapshot_paths(self) -> set[Path]:
        files: set[Path] = set()
        for root in self.roots:
            try:
                files.update(path.resolve() for path in self._file_lister(root, self.recursive))
            except OSError:
                # 임시 폴더 일부의 접근 거부 때문에 다른 감시 루트까지 놓치지 않는다.
                continue
        return files

    def _aware_now(self) -> datetime:
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("watcher clock must include a timezone offset")
        return current_time.astimezone(timezone.utc)
