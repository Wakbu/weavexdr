from __future__ import annotations

from collections import Counter, deque
from pathlib import PureWindowsPath

from xdr_graph.models import IncidentReport


RELATION_LABELS = {
    "runs": "실행",
    "spawns": "생성",
    "creates": "파일 생성",
    "connects": "외부 연결",
    "persists": "지속성 등록",
    "queries": "DNS 조회",
    "downloads": "다운로드 추정",
}


def analyze_graph(report: IncidentReport, baseline: list[IncidentReport] | None = None) -> dict[str, object]:
    """사건 원본 이벤트만으로 설명 가능한 관계·가설을 만든다.

    추론 결과에는 항상 근거 이벤트 ID를 넣는다. 로컬 AI가 근거 없는 관계를
    사실처럼 답하거나 UI가 관찰 관계와 추론을 혼동하지 않게 하기 위함이다.
    """
    nodes: dict[str, dict[str, str]] = {}
    edges: dict[tuple[str, str, str], dict[str, object]] = {}

    def add_node(key: str, kind: str, label: str) -> str:
        nodes.setdefault(key, {"id": key, "type": kind, "label": label})
        return key

    def add_edge(source: str, target: str, relation: str, event_id: str, *, inferred: bool = False) -> None:
        key = (source, target, relation)
        edge = edges.setdefault(key, {
            "source": source, "target": target, "relation": relation,
            "label": RELATION_LABELS[relation], "evidence_event_ids": [],
            "confidence": 0.72 if inferred else 0.96, "inferred": inferred,
        })
        if event_id not in edge["evidence_event_ids"]:
            edge["evidence_event_ids"].append(event_id)

    for event in sorted(report.source_events, key=lambda item: item.timestamp):
        host = add_node(f"host:{event.host_id}", "endpoint", event.host_id)
        process_name = getattr(event, "process_name", None)
        process_guid = getattr(event, "process_guid", None)
        process_id = getattr(event, "process_id", None)
        process = None
        if process_name:
            process = add_node(f"process:{process_guid or f'{process_name}:{process_id or 0}'}", "process", process_name)
            add_edge(host, process, "runs", event.event_id)
        if event.event_type == "process_start" and process:
            parent_name = getattr(event, "parent_process", None)
            if parent_name:
                parent_guid = getattr(event, "parent_process_guid", None)
                parent = add_node(f"parent:{parent_guid or parent_name}", "process", parent_name)
                add_edge(parent, process, "spawns", event.event_id)
        elif event.event_type == "file_create" and process:
            path = event.file_path
            file_node = add_node(f"file:{path}", "file", PureWindowsPath(path).name or path)
            add_edge(process, file_node, "creates", event.event_id)
        elif event.event_type == "network_connect" and process:
            inbound = event.initiated is False and event.source_ip
            address = event.source_ip if inbound else event.destination_ip
            ip_node = add_node(f"ip:{address}", "external", str(address))
            add_edge(ip_node, process, "connects", event.event_id) if inbound else add_edge(process, ip_node, "connects", event.event_id)
        elif event.event_type in {"registry_persistence", "service_install", "scheduled_task", "wmi_subscription"} and process:
            target = getattr(event, "target", None) or getattr(event, "action", None) or event.event_type
            persistence = add_node(f"persistence:{target}", "persistence", str(target))
            add_edge(process, persistence, "persists", event.event_id)
        elif event.event_type == "dns_query" and process:
            target = getattr(event, "target", None) or getattr(event, "destination_ip", None)
            if target:
                domain = add_node(f"domain:{target}", "external", str(target))
                add_edge(process, domain, "queries", event.event_id)

    # 동일 프로세스의 외부 연결 직후 파일 생성은 다운로드일 수 있지만 직접
    # 관찰된 사실은 아니므로 점선·낮은 신뢰도의 추론 관계로만 제공한다.
    for process_id in [key for key, value in nodes.items() if value["type"] == "process"]:
        network_edges = [edge for edge in edges.values() if edge["relation"] == "connects" and process_id in {edge["source"], edge["target"]}]
        file_edges = [edge for edge in edges.values() if edge["relation"] == "creates" and edge["source"] == process_id]
        for network_edge in network_edges:
            remote = network_edge["source"] if network_edge["source"] != process_id else network_edge["target"]
            for file_edge in file_edges:
                evidence_ids = [*network_edge["evidence_event_ids"], *file_edge["evidence_event_ids"]]
                for event_id in evidence_ids:
                    add_edge(remote, file_edge["target"], "downloads", event_id, inferred=True)

    baseline_counts: Counter[str] = Counter()
    for candidate in baseline or [report]:
        for event in candidate.source_events:
            process_name = (getattr(event, "process_name", None) or "unknown").casefold()
            parent = (getattr(event, "parent_process", None) or "").casefold()
            baseline_counts[f"{event.event_type}:{parent}:{process_name}"] += 1
    for edge in edges.values():
        source = nodes[edge["source"]]["label"].casefold()
        target = nodes[edge["target"]]["label"].casefold()
        edge["rare"] = baseline_counts[f"process_start:{source}:{target}"] <= 1 if edge["relation"] == "spawns" else False

    # 외부 노드에서 파일·지속성 노드까지의 가장 짧은 관찰 경로를 우선 제시한다.
    adjacency: dict[str, list[str]] = {}
    for edge in edges.values():
        adjacency.setdefault(edge["source"], []).append(edge["target"])
        adjacency.setdefault(edge["target"], []).append(edge["source"])
    starts = [key for key, value in nodes.items() if value["type"] == "external"]
    targets = {key for key, value in nodes.items() if value["type"] in {"file", "persistence"}}
    shortest: list[str] = []
    pending = deque((key, [key]) for key in starts)
    visited = set(starts)
    while pending and not shortest:
        current, path = pending.popleft()
        if current in targets:
            shortest = path
            break
        for target in adjacency.get(current, []):
            if target not in visited:
                visited.add(target)
                pending.append((target, [*path, target]))

    relation_counts = Counter(edge["relation"] for edge in edges.values())
    event_counts = Counter(event.timestamp.astimezone().strftime("%H") for event in report.source_events)
    hypotheses: list[dict[str, object]] = []
    if relation_counts["connects"] and relation_counts["creates"]:
        evidence = sorted({event_id for edge in edges.values() if edge["relation"] in {"connects", "creates"} for event_id in edge["evidence_event_ids"]})
        hypotheses.append({"title": "외부 통신과 파일 생성이 같은 실행 흐름에 포함됨", "confidence": 0.82, "evidence_event_ids": evidence})
    if relation_counts["persists"]:
        evidence = sorted({event_id for edge in edges.values() if edge["relation"] == "persists" for event_id in edge["evidence_event_ids"]})
        hypotheses.append({"title": "실행 후 지속성 확보를 시도했을 가능성", "confidence": 0.78, "evidence_event_ids": evidence})

    missing = []
    if not relation_counts["connects"]:
        missing.append("동일 시간대 네트워크 연결 이벤트")
    if not relation_counts["creates"]:
        missing.append("생성·변경 파일의 해시와 서명 정보")
    if not any(getattr(event, "user", None) for event in report.source_events):
        missing.append("실행 사용자와 로그인 세션 정보")

    connection_explanations = [
        {
            "source": nodes[edge["source"]]["label"],
            "target": nodes[edge["target"]]["label"],
            "why": f"{nodes[edge['source']]['label']} → {nodes[edge['target']]['label']}: {edge['label']}",
            "confidence": edge["confidence"],
            "evidence_event_ids": edge["evidence_event_ids"],
            "inferred": edge["inferred"],
        }
        for edge in edges.values()
    ]

    return {
        "nodes": list(nodes.values()), "edges": list(edges.values()),
        "relation_counts": {RELATION_LABELS[key]: value for key, value in relation_counts.items()},
        "rare_relation_count": sum(bool(edge["rare"]) for edge in edges.values()),
        "shortest_path": shortest,
        "shortest_path_labels": [nodes[key]["label"] for key in shortest],
        "hypotheses": hypotheses,
        "missing_evidence": missing,
        "connection_explanations": connection_explanations,
        "hourly_activity": [{"hour": f"{hour:02d}", "count": event_counts[f"{hour:02d}"]} for hour in range(24)],
    }
