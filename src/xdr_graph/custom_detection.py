from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from threading import Event, Thread

from xdr_graph.storage import SQLiteEventStore


LOGGER = logging.getLogger(__name__)


class CustomDetectionService:
    """저장 헌팅을 제한된 SQL 집계로 반복 실행하는 로컬 탐지 서비스."""

    def __init__(self, store: SQLiteEventStore, *, poll_seconds: float = 15.0) -> None:
        self.store = store
        self.poll_seconds = max(1.0, poll_seconds)
        self._stop = Event()
        self._thread: Thread | None = None

    @staticmethod
    def _query_arguments(filters: dict[str, object]) -> tuple[dict[str, object], int]:
        try:
            window_hours = max(1, min(720, int(filters.get("window") or 168)))
        except (TypeError, ValueError):
            window_hours = 168
        date_from = (datetime.now(UTC) - timedelta(hours=window_hours)).isoformat()
        arguments: dict[str, object] = {"date_from": date_from}
        mappings = {"verdict": "verdict", "query": "query", "entity": "entity"}
        for source, target in mappings.items():
            value = filters.get(source)
            if value not in (None, ""):
                arguments[target] = str(value)
        risk = filters.get("risk", filters.get("min_risk"))
        if risk not in (None, ""):
            arguments["min_risk"] = int(risk)
        return arguments, window_hours

    def run(self, detection_id: int) -> dict[str, object]:
        detection = self.store.get_custom_detection(detection_id)
        if detection is None:
            raise KeyError("custom detection was not found")
        search = self.store.get_saved_search(int(detection["search_id"]))
        if search is None:
            raise KeyError("saved hunting condition was not found")
        arguments, window_hours = self._query_arguments(search["filters"])
        # 전체 예상량은 COUNT 쿼리 한 번으로 계산하고 화면 근거는 최대 100건만 읽어
        # 사건이 수천 건이어도 메모리와 JSON 직렬화 비용이 선형으로 커지지 않게 한다.
        match_count = self.store.filtered_incident_count(**arguments)
        samples = self.store.list_incident_views(
            limit=100, offset=0, sort="risk_desc", **arguments
        )
        daily = round(match_count * 24 / window_hours, 2)
        return self.store.update_custom_detection_run(
            detection_id,
            match_count=match_count,
            estimated_daily_matches=daily,
            sample_incident_ids=[str(item["incident_id"]) for item in samples],
        ) or detection

    def run_due(self) -> int:
        now = datetime.now(UTC)
        due = 0
        for detection in self.store.list_custom_detections():
            if detection["state"] == "paused":
                continue
            next_run = detection.get("next_run_at")
            if next_run and datetime.fromisoformat(str(next_run)) > now:
                continue
            try:
                self.run(int(detection["detection_id"]))
                due += 1
            except Exception:
                LOGGER.exception("custom detection repeat run failed: %s", detection["detection_id"])
        return due

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def repeat() -> None:
            while not self._stop.wait(self.poll_seconds):
                self.run_due()

        self._thread = Thread(target=repeat, name="weavexdr-custom-detections", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
