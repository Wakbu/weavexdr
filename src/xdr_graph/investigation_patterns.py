"""여러 이벤트와 과거 사건을 결합하는 고급 조사 패턴을 계산한다.

단일 규칙 일치가 아니라 시간 순서와 엔터티 연속성이 필요한 탐지만 이 모듈에 둔다.
결과는 자동 판정이 아닌 조사 후보이며, 모든 후보가 원본 이벤트 ID와 판단 기준을
반환한다. 파일을 열거나 외부 조회를 하지 않으므로 그래프 API에서 안전하게 재계산할 수 있다.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PureWindowsPath
from time import perf_counter

from xdr_graph.models import IncidentReport, SecurityEvent


ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".iso", ".cab"}
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".js", ".vbs"}
PERSISTENCE_TYPES = {"registry_persistence", "service_install", "scheduled_task", "wmi_subscription"}


def _event_path(event: SecurityEvent) -> str:
    return str(getattr(event, "file_path", None) or getattr(event, "image_path", None) or "")


def _event_text(event: SecurityEvent) -> str:
    details = getattr(event, "details", {}) or {}
    return " ".join(
        str(value or "")
        for value in (
            getattr(event, "process_name", None),
            getattr(event, "command_line", None),
            getattr(event, "image_path", None),
            getattr(event, "file_path", None),
            getattr(event, "target", None),
            details.get("source_path"),
            details.get("original_file_name"),
        )
    ).casefold()


def _suffix(path: str) -> str:
    return PureWindowsPath(path).suffix.casefold() if path else ""


def detect_advanced_chains(events: list[SecurityEvent]) -> list[dict[str, object]]:
    """시간순 이벤트에서 다단계 유입·실행·위장 패턴을 조사 후보로 만든다.

    각 단계는 앞 단계 이후 30분 안에 있어야 한다. 단순히 네 종류 이벤트가 사건에
    존재한다는 이유만으로 연결하지 않고, 생성된 실행 파일의 이름이 실제 프로세스
    이미지나 명령줄에 나타날 때만 실행 단계로 인정한다.
    """
    started = perf_counter()
    ordered = sorted(events, key=lambda event: event.timestamp)
    chains: list[dict[str, object]] = []

    archives = [event for event in ordered if event.event_type == "file_create" and _suffix(_event_path(event)) in ARCHIVE_SUFFIXES]
    executables = [event for event in ordered if event.event_type == "file_create" and _suffix(_event_path(event)) in EXECUTABLE_SUFFIXES]
    for archive in archives:
        archive_process = str(getattr(archive, "process_guid", None) or getattr(archive, "process_name", None) or "").casefold()
        download = next(
            (
                event
                for event in reversed(ordered)
                if event.event_type == "network_connect"
                and 0 <= (archive.timestamp - event.timestamp).total_seconds() <= 10 * 60
                and archive_process
                and archive_process == str(getattr(event, "process_guid", None) or getattr(event, "process_name", None) or "").casefold()
            ),
            None,
        )
        if download is None:
            continue
        deadline = archive.timestamp.timestamp() + 30 * 60
        extracted = next(
            (event for event in executables if archive.timestamp <= event.timestamp and event.timestamp.timestamp() <= deadline),
            None,
        )
        if extracted is None:
            continue
        executable_name = PureWindowsPath(_event_path(extracted)).name.casefold()
        executed = next(
            (
                event
                for event in ordered
                if event.event_type == "process_start"
                and extracted.timestamp <= event.timestamp
                and event.timestamp.timestamp() <= deadline
                and executable_name
                and executable_name in _event_text(event)
            ),
            None,
        )
        if executed is None:
            continue
        persistence = next(
            (
                event
                for event in ordered
                if event.event_type in PERSISTENCE_TYPES
                and executed.timestamp <= event.timestamp
                and event.timestamp.timestamp() <= deadline
            ),
            None,
        )
        event_ids = [download.event_id, archive.event_id, extracted.event_id, executed.event_id]
        if persistence:
            event_ids.append(persistence.event_id)
        chains.append(
            {
                "kind": "다운로드·압축 해제·실행·지속성",
                "score": 92 if persistence else 78,
                "detail": "압축 파일 뒤 생성된 실행 파일이 실제 실행되고 지속성 단계까지 이어짐" if persistence else "압축 파일 뒤 생성된 실행 파일이 30분 안에 실행됨",
                "event_ids": event_ids,
                "observed_stages": 5 if persistence else 4,
                "analysis_ms": round((perf_counter() - started) * 1000, 3),
            }
        )
        break

    # UNC 경로는 로컬 드라이브와 달리 네트워크 공유 유입을 직접 나타낸다. 공유에서
    # 생성·관찰된 파일 이름이 이후 프로세스 문맥에 등장해야 실행 연쇄로 올린다.
    share_files = [event for event in ordered if _event_path(event).startswith("\\\\")]
    for source in share_files:
        file_name = PureWindowsPath(_event_path(source)).name.casefold()
        executed = next(
            (
                event
                for event in ordered
                if event.event_type == "process_start"
                and event.timestamp >= source.timestamp
                and file_name
                and file_name in _event_text(event)
            ),
            None,
        )
        chains.append(
            {
                "kind": "네트워크 공유 파일 유입",
                "score": 79 if executed else 55,
                "detail": "UNC 공유 경로의 파일이 이후 실행 문맥과 연결됨" if executed else "UNC 공유 경로 파일을 관찰했으나 실행 근거는 없음",
                "event_ids": [source.event_id, *([executed.event_id] if executed else [])],
                "observed_stages": 2 if executed else 1,
                "analysis_ms": round((perf_counter() - started) * 1000, 3),
            }
        )
        break
    return chains


def detect_file_identity_changes(
    current: IncidentReport, baseline: list[IncidentReport]
) -> list[dict[str, object]]:
    """같은 파일 이름의 경로·해시·서명자 변화를 과거 관찰과 비교한다.

    동일 이름만으로 악성이라고 단정하지 않는다. 서로 다른 경로나 해시가 실제로 둘
    이상 관찰된 경우에만 후보를 만들고, 현재 사건 이벤트가 포함된 그룹만 반환한다.
    """
    variants: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    current_ids = {event.event_id for event in current.source_events}
    for report in baseline:
        for event in report.source_events:
            path = _event_path(event)
            if not path:
                continue
            name = PureWindowsPath(path).name.casefold()
            hashes = getattr(event, "file_hashes", {}) or {}
            digest = next(iter(hashes.values()), "")
            signer = str(getattr(event, "file_signer", None) or "")
            variants[name].append(
                {"path": path.casefold(), "hash": digest.casefold(), "signer": signer.casefold(), "event_id": event.event_id, "incident_id": report.incident_id}
            )

    results = []
    for name, rows in variants.items():
        if not current_ids.intersection(row["event_id"] for row in rows):
            continue
        paths = {row["path"] for row in rows if row["path"]}
        hashes = {row["hash"] for row in rows if row["hash"]}
        signers = {row["signer"] for row in rows if row["signer"]}
        changed = [label for label, values in (("경로", paths), ("해시", hashes), ("서명자", signers)) if len(values) > 1]
        if not changed:
            continue
        results.append(
            {
                "kind": "파일 신원 연쇄 변경",
                "score": min(90, 58 + len(changed) * 10),
                "detail": f"{name}의 {'·'.join(changed)} 변경이 과거 사건과 비교해 관찰됨",
                "event_ids": sorted({row["event_id"] for row in rows}),
                "changed_fields": changed,
                "incident_ids": sorted({row["incident_id"] for row in rows}),
            }
        )
    return results[:10]


def historical_subgraph_overlay(
    report: IncidentReport,
    baseline: list[IncidentReport],
    node_lookup: dict[tuple[str, str], list[str]],
) -> list[dict[str, object]]:
    """현재 엔터티가 등장한 과거 사건과 현재 그래프 노드 ID를 연결한다."""
    current_entities = {
        str(value).casefold()
        for event in report.source_events
        for value in (getattr(event, "process_name", None), getattr(event, "destination_ip", None), _event_path(event))
        if value
    }
    overlays = []
    for candidate in baseline:
        if candidate.incident_id == report.incident_id:
            continue
        candidate_entities = {
            str(value).casefold()
            for event in candidate.source_events
            for value in (getattr(event, "process_name", None), getattr(event, "destination_ip", None), _event_path(event))
            if value
        }
        shared = sorted(current_entities & candidate_entities)
        if not shared:
            continue
        node_ids = sorted({node_id for entity in shared for node_id in node_lookup.get(("label", entity), [])})
        overlays.append({"incident_id": candidate.incident_id, "shared_entities": shared, "node_ids": node_ids, "shared_count": len(shared)})
    return sorted(overlays, key=lambda row: (-row["shared_count"], row["incident_id"]))[:12]


def graph_review_hints(
    nodes: dict[str, dict[str, str]],
    edges: list[dict[str, object]],
    attack_paths: list[list[str]],
) -> dict[str, object]:
    """핵심 경로 외 잡음 노드와 안전한 노드 병합 후보를 계산한다."""
    core = {node_id for path in attack_paths for node_id in path}
    for edge in edges:
        if edge.get("rare") or int(edge.get("risk_contribution", 0)) >= 20:
            core.update((str(edge["source"]), str(edge["target"])))
    if not core:
        core = {node_id for node_id, node in nodes.items() if node["type"] in {"process", "external", "persistence"}}
    noise = sorted(set(nodes) - core)

    groups: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
    for node_id, node in nodes.items():
        groups[(node["type"], node["label"].casefold())].append(node_id)
    suggestions = [
        {
            "type": kind,
            "label": nodes[node_ids[0]]["label"],
            "node_ids": sorted(node_ids),
            "confidence": 0.72,
            "reason": "표시 이름과 엔터티 유형은 같지만 수집 식별자가 달라 별도 노드로 존재",
        }
        for (kind, _), node_ids in groups.items()
        if len(node_ids) > 1
    ]
    return {"core_node_ids": sorted(core), "noise_node_ids": noise, "merge_suggestions": suggestions[:20]}
