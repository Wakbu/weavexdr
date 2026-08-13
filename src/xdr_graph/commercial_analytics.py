from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable

from xdr_graph.models import IncidentReport


def _event_entities(event: object) -> set[tuple[str, str]]:
    """Return normalized pivots that are useful in a single-PC investigation."""
    values: set[tuple[str, str]] = set()
    fields = (
        ("host", getattr(event, "host_id", None)),
        ("user", getattr(event, "user", None)),
        ("process", getattr(event, "process_name", None)),
        ("file", getattr(event, "file_path", None)),
        ("ip", getattr(event, "destination_ip", None)),
        ("ip", getattr(event, "source_ip", None)),
    )
    for kind, raw_value in fields:
        if not raw_value:
            continue
        value = str(raw_value).strip()
        if not value or value.lower() in {"unknown", "none"}:
            continue
        # 전체 경로는 같은 파일의 피벗을 지나치게 길게 만들므로 화면용 이름만
        # 별도 생성하되 원문 검색이 가능한 값은 그대로 유지한다.
        display = Path(value).name if kind == "file" else value
        values.add((kind, display or value))
    return values


def analyze_security_portfolio(
    reports: Iterable[IncidentReport], *, window_hours: int = 168
) -> dict[str, object]:
    """Build entity risk and deterministic attack stories without external upload."""
    if window_hours not in {1, 6, 24, 168, 720}:
        raise ValueError("invalid hunting time window")
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
    selected: list[IncidentReport] = []
    incident_entities: dict[str, set[tuple[str, str]]] = {}
    entity_incidents: dict[tuple[str, str], list[IncidentReport]] = defaultdict(list)

    for report in reports:
        recent_events = [event for event in report.source_events if event.timestamp >= cutoff]
        if not recent_events:
            continue
        selected.append(report)
        entities = {entity for event in recent_events for entity in _event_entities(event)}
        incident_entities[report.incident_id] = entities
        for entity in entities:
            entity_incidents[entity].append(report)

    entity_rows: list[dict[str, object]] = []
    for (kind, value), related in entity_incidents.items():
        peak = max(report.risk_score for report in related)
        suspicious = sum(report.verdict == "suspicious" for report in related)
        review = sum(report.verdict == "needs_review" for report in related)
        # 최고 위험도를 중심으로 반복 관찰과 고위험 판정이 조금씩 우선순위를
        # 높인다. 이 값은 사건의 원래 위험 점수를 변경하지 않는 조사용 점수다.
        score = min(100, round(peak * 0.72 + min(18, len(related) * 3) + suspicious * 7 + review * 2))
        entity_rows.append({
            "type": kind,
            "value": value,
            "risk_score": score,
            "incident_count": len(related),
            "suspicious_count": suspicious,
            "latest_incident_id": related[0].incident_id,
        })
    entity_rows.sort(key=lambda row: (-int(row["risk_score"]), -int(row["incident_count"]), str(row["value"])))

    # 공유 엔터티가 있는 사건을 union-find로 묶어 경보 목록 대신 공격 단위로 본다.
    parents = {report.incident_id: report.incident_id for report in selected}

    def find(item: str) -> str:
        while parents[item] != item:
            parents[item] = parents[parents[item]]
            item = parents[item]
        return item

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for (kind, _), related in entity_incidents.items():
        # local-host 하나만으로 모든 사건이 합쳐지는 것을 방지한다.
        if kind == "host" or len(related) < 2:
            continue
        first = related[0].incident_id
        for report in related[1:]:
            union(first, report.incident_id)

    groups: dict[str, list[IncidentReport]] = defaultdict(list)
    for report in selected:
        groups[find(report.incident_id)].append(report)

    stories: list[dict[str, object]] = []
    for grouped in groups.values():
        if len(grouped) == 1 and grouped[0].risk_score < 70:
            continue
        ids = {report.incident_id for report in grouped}
        shared = [
            {"type": kind, "value": value, "incident_count": len({item.incident_id for item in related if item.incident_id in ids})}
            for (kind, value), related in entity_incidents.items()
            if len({item.incident_id for item in related if item.incident_id in ids}) >= 2
        ]
        shared.sort(key=lambda row: (-int(row["incident_count"]), str(row["value"])))
        rules = {finding.rule_id for report in grouped for finding in report.findings}
        techniques = {
            reference.external_id
            for report in grouped for finding in report.findings for reference in finding.references
            if reference.framework == "mitre_attack"
        }
        peak = max(report.risk_score for report in grouped)
        confidence = min(99, 35 + len(grouped) * 8 + len(rules) * 5 + len(techniques) * 4 + len(shared) * 3)
        pivot = shared[0]["value"] if shared else grouped[0].incident_id
        stories.append({
            "story_id": f"story-{grouped[0].incident_id}",
            "title": f"{pivot} 중심의 연관 활동",
            "incident_ids": [report.incident_id for report in grouped],
            "incident_count": len(grouped),
            "peak_risk": peak,
            "confidence": confidence,
            "shared_entities": shared[:8],
            "rule_count": len(rules),
            "mitre_techniques": sorted(techniques),
        })
    stories.sort(key=lambda row: (-int(row["peak_risk"]), -int(row["confidence"])))

    return {
        "window_hours": window_hours,
        "incident_count": len(selected),
        "high_risk_entities": sum(int(row["risk_score"]) >= 70 for row in entity_rows),
        "entities": entity_rows[:50],
        "stories": stories[:20],
        "generated_at": datetime.now(UTC).isoformat(),
        "privacy": "local_only",
    }
