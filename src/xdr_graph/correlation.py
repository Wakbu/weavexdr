from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from hashlib import sha256
from typing import Sequence

from xdr_graph.models import (
    AttackChain,
    Finding,
    ProcessStartEvent,
    SecurityEvent,
    ThreatReference,
)


class EventCorrelationEngine:
    """프로세스 계보와 제한된 시간 범위로 서로 다른 이벤트 증거를 연결한다."""

    def __init__(self, *, time_window: timedelta = timedelta(minutes=5)) -> None:
        if time_window.total_seconds() <= 0:
            raise ValueError("time_window must be positive")
        self.time_window = time_window

    def correlate(
        self, events: Sequence[SecurityEvent]
    ) -> tuple[list[AttackChain], list[Finding]]:
        process_events = [
            event for event in events if isinstance(event, ProcessStartEvent)
        ]
        by_guid = {
            self._normalized_guid(event.process_guid): event
            for event in process_events
            if event.process_guid
        }
        root_groups: dict[str, set[str]] = defaultdict(set)

        for process_event in process_events:
            root_event = self._find_root(process_event, by_guid)
            root_key = self._process_key(root_event)
            root_groups[root_key].add(self._process_key(process_event))

        # ProcessGuid가 없는 수집원도 PID와 시작 시각을 조합해 같은 프로세스를 연결한다.
        for event in events:
            event_key = self._process_key(event)
            if not event_key:
                continue
            if not any(event_key in members for members in root_groups.values()):
                root_groups[event_key].add(event_key)

        chains: list[AttackChain] = []
        findings: list[Finding] = []
        for root_key, member_keys in root_groups.items():
            related_events = [
                event for event in events if self._process_key(event) in member_keys
            ]
            if not related_events:
                continue
            related_events.sort(key=lambda event: (event.timestamp, event.event_id))
            started_at = related_events[0].timestamp
            ended_at = related_events[-1].timestamp
            # 멀리 떨어진 정상 활동을 하나의 공격 흐름으로 합쳐 오탐을 만들지 않는다.
            if ended_at - started_at > self.time_window:
                continue
            event_types = sorted({event.event_type for event in related_events})
            process_ids = [
                event.event_id
                for event in related_events
                if event.event_type == "process_start"
            ]
            if not process_ids:
                continue
            evidence_ids = [event.event_id for event in related_events]
            chain_digest = sha256("|".join(evidence_ids).encode("utf-8")).hexdigest()[:12]
            chain = AttackChain(
                chain_id=f"chain-{chain_digest}",
                root_process_event_id=process_ids[0],
                process_event_ids=process_ids,
                evidence_event_ids=evidence_ids,
                event_types=event_types,
                started_at=started_at,
                ended_at=ended_at,
            )
            chains.append(chain)

            if len(event_types) >= 2:
                findings.append(
                    Finding(
                        source="behavior",
                        rule_id="CORR-001",
                        # 연결 자체는 기존 증거의 설명력을 높이지만 같은 이벤트에
                        # 점수를 다시 더하면 이중 계산이 된다. 따라서 추적용 0점 근거로 남긴다.
                        severity=0,
                        reason="Multiple security event types formed one process-linked attack chain",
                        event_ids=evidence_ids,
                        references=[
                            ThreatReference(
                                framework="mitre_attack",
                                external_id="T1059",
                                url="https://attack.mitre.org/techniques/T1059/",
                            )
                        ],
                    )
                )
        return chains, findings

    def _find_root(
        self,
        process_event: ProcessStartEvent,
        by_guid: dict[str, ProcessStartEvent],
    ) -> ProcessStartEvent:
        current = process_event
        visited: set[str] = set()
        while current.parent_process_guid:
            parent_guid = self._normalized_guid(current.parent_process_guid)
            if parent_guid in visited or parent_guid not in by_guid:
                break
            visited.add(parent_guid)
            current = by_guid[parent_guid]
        return current

    @staticmethod
    def _normalized_guid(value: str | None) -> str:
        return (value or "").strip().lower()

    @classmethod
    def _process_key(cls, event: SecurityEvent) -> str:
        process_guid = getattr(event, "process_guid", None)
        if process_guid:
            return f"guid:{cls._normalized_guid(process_guid)}"
        process_id = getattr(event, "process_id", None)
        start_time = getattr(event, "process_start_time", None)
        if process_id is None or start_time is None:
            return ""
        return f"pid:{event.host_id}:{process_id}:{start_time.isoformat()}"
