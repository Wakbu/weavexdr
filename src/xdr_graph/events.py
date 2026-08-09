from __future__ import annotations

from queue import Empty, Queue
from threading import RLock
from typing import Protocol

from xdr_graph.models import IncidentReport


class IncidentPublisher(Protocol):
    def publish(self, report: IncidentReport) -> None: ...


class IncidentEventBroker:
    """로컬 API 구독자에게 새 사건 보고서를 전달하는 제한 용량 브로커."""

    def __init__(self, *, queue_size: int = 100) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")
        self.queue_size = queue_size
        self._lock = RLock()
        self._subscribers: set[Queue[IncidentReport]] = set()

    def subscribe(self) -> Queue[IncidentReport]:
        subscriber: Queue[IncidentReport] = Queue(maxsize=self.queue_size)
        with self._lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: Queue[IncidentReport]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, report: IncidentReport) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            if subscriber.full():
                # 느린 화면 때문에 수집 경로가 멈추지 않도록 가장 오래된 알림만 버린다.
                try:
                    subscriber.get_nowait()
                except Empty:
                    pass
            subscriber.put_nowait(report)
