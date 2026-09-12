"""사건 이벤트를 설명 가능한 엔터티 그래프와 조사 가설로 변환한다.

노드와 엣지는 dict 해시 키로 중복을 제거하고, 최단 경로는 deque 기반 BFS로 계산한다.
추론 관계는 관찰 관계와 다른 신뢰도로 표시하며 모든 결과에 원본 이벤트 ID를 남긴다.
경로 열거는 홉·개수 상한을 둬 순환 그래프의 조합 폭발을 방지한다.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from pathlib import PureWindowsPath
from time import perf_counter

from xdr_graph.investigation_patterns import (
    detect_advanced_chains,
    detect_file_identity_changes,
    graph_review_hints,
    historical_subgraph_overlay,
)
from xdr_graph.models import IncidentReport


RELATION_LABELS = {
    "runs": "실행",
    "spawns": "생성",
    "creates": "파일 생성",
    "connects": "외부 연결",
    "persists": "지속성 등록",
    "queries": "DNS 조회",
    "downloads": "다운로드 추정",
    "authenticates": "인증",
}

RELATION_STYLES = {
    "runs": "execution", "spawns": "spawn", "creates": "file",
    "connects": "network", "persists": "persistence", "queries": "dns",
    "downloads": "download",
    "authenticates": "authentication",
}


def find_attack_path(insights: dict[str, object], start_node_id: str, end_node_id: str) -> dict[str, object]:
    """사용자가 고른 두 노드 사이의 최단 방향 경로를 제한 BFS로 찾는다.

    서버가 반환한 노드 ID만 허용하고 각 노드를 한 번만 방문한다. 따라서 잘못된 ID나
    순환 관계가 들어와도 탐색 비용은 O(V+E)를 넘지 않으며 그래프를 변경하지 않는다.
    """
    node_ids = {str(node["id"]) for node in insights.get("nodes", [])}
    if start_node_id not in node_ids or end_node_id not in node_ids:
        raise ValueError("start and end nodes must exist in this incident graph")
    pending = deque([(start_node_id, [start_node_id])])
    visited = {start_node_id}
    adjacency: defaultdict[str, list[str]] = defaultdict(list)
    for edge in insights.get("edges", []):
        adjacency[str(edge["source"])].append(str(edge["target"]))
    while pending:
        current, path = pending.popleft()
        if current == end_node_id:
            return {"start_node_id": start_node_id, "end_node_id": end_node_id, "path": path, "hop_count": len(path) - 1}
        for candidate in adjacency[current]:
            if candidate not in visited:
                visited.add(candidate)
                pending.append((candidate, [*path, candidate]))
    return {"start_node_id": start_node_id, "end_node_id": end_node_id, "path": [], "hop_count": None}


def compare_response_graph(insights: dict[str, object], blocked_node_ids: list[str]) -> dict[str, object]:
    """가상 차단 전후의 경로와 잔여 위험을 계산하되 실제 시스템은 변경하지 않는다.

    UI에서 받은 ID는 현재 사건 그래프에 존재하는 값만 허용한다. 공격 경로가 있으면
    차단 뒤 남은 경로 비율을, 경로가 없으면 남은 관계 위험 기여도 비율을 사용한다.
    이는 대응 우선순위 비교용 추정치이며 실제 차단 성공 판정으로 사용하지 않는다.
    """
    nodes = insights.get("nodes", [])
    edges = insights.get("edges", [])
    valid_ids = {str(node["id"]) for node in nodes}
    blocked = set(blocked_node_ids)
    if not blocked or not blocked <= valid_ids:
        raise ValueError("blocked nodes must exist in this incident graph")

    before_paths = [list(path) for path in insights.get("attack_paths", [])]
    after_paths = [path for path in before_paths if blocked.isdisjoint(path)]
    before_edge_indexes = list(range(len(edges)))
    after_edge_indexes = [
        index for index, edge in enumerate(edges)
        if edge["source"] not in blocked and edge["target"] not in blocked
    ]
    if before_paths:
        residual_ratio = len(after_paths) / len(before_paths)
    else:
        before_weight = max(1, sum(int(edge.get("risk_contribution", 0)) for edge in edges))
        after_weight = sum(int(edges[index].get("risk_contribution", 0)) for index in after_edge_indexes)
        residual_ratio = after_weight / before_weight
    before_risk = int(insights.get("incident_risk_score", 0))
    after_risk = round(before_risk * residual_ratio)
    after_nodes = sorted({
        node_id for index in after_edge_indexes
        for node_id in (str(edges[index]["source"]), str(edges[index]["target"]))
    })
    target_ids = set(insights.get("blast_radius", {}).get("target_node_ids", []))
    return {
        "blocked_node_ids": sorted(blocked),
        "before": {"node_ids": sorted(valid_ids), "edge_indexes": before_edge_indexes, "path_count": len(before_paths), "risk": before_risk},
        "after": {
            "node_ids": after_nodes, "edge_indexes": after_edge_indexes,
            "path_count": len(after_paths), "risk": after_risk,
            "reachable_target_node_ids": sorted({path[-1] for path in after_paths if path and path[-1] in target_ids}),
        },
        "removed_edge_indexes": sorted(set(before_edge_indexes) - set(after_edge_indexes)),
        "risk_reduction": before_risk - after_risk,
        "residual_risk": after_risk,
        "simulation_only": True,
    }


def analyze_graph(report: IncidentReport, baseline: list[IncidentReport] | None = None) -> dict[str, object]:
    """사건 원본 이벤트만으로 설명 가능한 관계·가설을 만든다.

    추론 결과에는 항상 근거 이벤트 ID를 넣는다. 로컬 AI가 근거 없는 관계를
    사실처럼 답하거나 UI가 관찰 관계와 추론을 혼동하지 않게 하기 위함이다.

    노드 조회와 엣지 중복 제거는 dict/set의 평균 O(1) 연산을 사용한다. 최단 경로 BFS는
    O(V+E), 제한 경로 탐색은 최대 6홉·8개 결과에서 중단한다. `baseline`은 희귀도를
    계산하는 비교 집합일 뿐 현재 사건의 판정이나 원본 관계를 변경하지 않는다.
    """
    analysis_started = perf_counter()
    # 엔터티 자연키와 (source, target, relation) 튜플을 해시 키로 사용한다. 같은
    # 이벤트가 재수집되어도 노드·선이 중복되지 않고 근거 ID만 합쳐진다.
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
        elif event.event_type == "authentication":
            user_label = getattr(event, "user", None) or "알 수 없는 사용자"
            user = add_node(f"identity:{user_label.casefold()}", "identity", user_label)
            add_edge(user, host, "authenticates", event.event_id)

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

    # 희귀도는 부모-자식 이름과 이벤트 유형의 빈도다. baseline이 없을 때 현재 사건만
    # 사용하므로 “처음 관찰”은 절대적인 전역 신규성이 아니라 현재 보유 데이터 기준이다.
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

    event_by_id = {event.event_id: event for event in report.source_events}
    relation_risk = {"runs": 4, "spawns": 14, "creates": 18, "connects": 16, "persists": 24, "queries": 9, "downloads": 22, "authenticates": 12}
    for edge in edges.values():
        observed = [event_by_id[event_id].timestamp for event_id in edge["evidence_event_ids"] if event_id in event_by_id]
        edge["first_seen"] = min(observed).isoformat() if observed else None
        edge["last_seen"] = max(observed).isoformat() if observed else None
        edge["risk_contribution"] = min(40, relation_risk[edge["relation"]] + max(0, len(edge["evidence_event_ids"]) - 1) * 2)
        edge["first_observed"] = edge["rare"]
        edge["source_label"] = nodes[edge["source"]]["label"]
        edge["target_label"] = nodes[edge["target"]]["label"]
        edge["style"] = RELATION_STYLES[edge["relation"]]

    # 외부 노드에서 파일·지속성 노드까지의 가장 짧은 관찰 경로를 우선 제시한다.
    adjacency: dict[str, list[str]] = {}
    for edge in edges.values():
        adjacency.setdefault(edge["source"], []).append(edge["target"])
    starts = [key for key, value in nodes.items() if value["type"] == "external"]
    targets = {key for key, value in nodes.items() if value["type"] in {"file", "persistence"}}
    shortest: list[str] = []
    # 여러 외부 시작점을 큐에 동시에 넣는 다중 소스 BFS다. 처음 도달한 파일·지속성
    # 노드의 경로가 간선 수 기준 최단 경로이며, visited로 순환 재방문을 막는다.
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

    # 분기 비교를 위해 단순 경로를 제한적으로 열거한다. 사건 하나에서 무한 순환이나
    # 조합 폭발이 생기지 않도록 최대 6홉·8개 경로까지만 반환한다.
    attack_paths: list[list[str]] = []
    pending_paths = deque((start, [start]) for start in starts)
    while pending_paths and len(attack_paths) < 8:
        current, path = pending_paths.popleft()
        if current in targets and len(path) > 1:
            attack_paths.append(path)
            continue
        if len(path) >= 7:
            continue
        for candidate in adjacency.get(current, []):
            if candidate not in path:
                pending_paths.append((candidate, [*path, candidate]))
    path_counts = Counter(node_id for path in attack_paths for node_id in path)
    common_path_nodes = [node_id for node_id, count in path_counts.items() if count > 1]
    # 시작·표적을 제외하고 여러 공격 경로가 겹치는 노드를 병목점으로 본다.
    # 경로 개수와 홉 상한은 위에서 이미 제한했으므로 큰 사건에서도 계산량이 작다.
    choke_points = [
        {"node_id": node_id, "path_count": count, "label": nodes[node_id]["label"], "type": nodes[node_id]["type"]}
        for node_id, count in path_counts.most_common()
        if count > 1 and node_id not in set(starts) | targets
    ]
    edge_indexes_by_pair = {
        frozenset((str(edge["source"]), str(edge["target"]))): index
        for index, edge in enumerate(edges.values())
    }
    blast_paths = []
    for path in attack_paths:
        edge_indexes = [
            edge_indexes_by_pair[frozenset((left, right))]
            for left, right in zip(path, path[1:])
            if frozenset((left, right)) in edge_indexes_by_pair
        ]
        blast_paths.append({
            "node_ids": path,
            "edge_indexes": edge_indexes,
            "potential": any(list(edges.values())[index]["inferred"] for index in edge_indexes),
        })
    blast_radius = {
        "entry_node_ids": sorted(starts),
        "target_node_ids": sorted(targets),
        "reachable_node_ids": sorted({node_id for path in attack_paths for node_id in path}),
        "choke_points": choke_points,
        "paths": blast_paths,
        "observed_path_count": sum(not path["potential"] for path in blast_paths),
        "potential_path_count": sum(path["potential"] for path in blast_paths),
    }

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

    baseline_reports = baseline or [report]
    process_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    weekly_counts: Counter[tuple[int, int]] = Counter()
    ioc_incidents: defaultdict[str, set[str]] = defaultdict(set)
    for candidate in baseline_reports:
        for event in candidate.source_events:
            if process_name := getattr(event, "process_name", None):
                process_counts[process_name.casefold()] += 1
            if user := getattr(event, "user", None):
                user_counts[user.casefold()] += 1
            host_counts[event.host_id.casefold()] += 1
            local_time = event.timestamp.astimezone()
            weekly_counts[(local_time.weekday(), local_time.hour)] += 1
            for ioc in (getattr(event, "destination_ip", None), getattr(event, "source_ip", None), getattr(event, "file_path", None)):
                if ioc:
                    ioc_incidents[str(ioc).casefold()].add(candidate.incident_id)

    baseline_rows = []
    for event in report.source_events:
        for kind, value, counts in (
            ("프로세스", getattr(event, "process_name", None), process_counts),
            ("사용자", getattr(event, "user", None), user_counts),
            ("호스트", event.host_id, host_counts),
        ):
            if value and not any(row["type"] == kind and row["value"] == value for row in baseline_rows):
                count = counts[str(value).casefold()]
                baseline_rows.append({"type": kind, "value": value, "observations": count, "rare": count <= 1})

    # 프로세스를 중심으로 인접 노드를 묶어 큰 그래프에서도 조사 단위를 바로 찾는다.
    clusters = []
    for process_id in [key for key, value in nodes.items() if value["type"] == "process"]:
        members = {process_id}
        for edge in edges.values():
            if edge["source"] == process_id:
                members.add(edge["target"])
            if edge["target"] == process_id:
                members.add(edge["source"])
        cluster_edges = [edge for edge in edges.values() if edge["source"] in members and edge["target"] in members]
        clusters.append({
            "id": f"cluster-{len(clusters)+1}", "label": nodes[process_id]["label"],
            "node_ids": sorted(members), "risk": min(100, sum(edge["risk_contribution"] for edge in cluster_edges)),
            "summary": f"{len(members)}개 노드 · {len(cluster_edges)}개 관계",
        })

    ordered_events = sorted(report.source_events, key=lambda event: event.timestamp)
    playback = []
    visible_events: set[str] = set()
    for index, event in enumerate(ordered_events, 1):
        visible_events.add(event.event_id)
        playback.append({
            "index": index, "event_id": event.event_id, "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "visible_edges": [position for position, edge in enumerate(edges.values()) if visible_events.intersection(edge["evidence_event_ids"])],
        })

    node_ids = list(nodes)[:30]
    adjacency_matrix = [[0 for _ in node_ids] for _ in node_ids]
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    for edge in edges.values():
        if edge["source"] in node_index and edge["target"] in node_index:
            left, right = node_index[edge["source"]], node_index[edge["target"]]
            adjacency_matrix[left][right] += 1
            adjacency_matrix[right][left] += 1

    event_risk: defaultdict[str, int] = defaultdict(int)
    for finding in report.findings:
        for event_id in finding.event_ids:
            event_risk[event_id] += finding.severity
    cumulative = 0
    risk_timeline = []
    for event in ordered_events:
        cumulative = min(100, cumulative + event_risk[event.event_id])
        risk_timeline.append({"event_id": event.event_id, "timestamp": event.timestamp.isoformat(), "risk": cumulative, "reason_count": sum(event.event_id in finding.event_ids for finding in report.findings)})

    stage_for_type = {
        "authentication": "초기 접근", "process_start": "실행", "powershell_script": "실행",
        "file_create": "파일 변경", "registry_persistence": "지속성", "service_install": "지속성",
        "scheduled_task": "지속성", "wmi_subscription": "지속성", "network_connect": "외부 통신",
        "dns_query": "외부 통신", "defender_detection": "영향",
    }
    stage_counts = Counter(stage_for_type.get(event.event_type, "기타") for event in ordered_events)
    # 작은 다중 그래프는 단계별 이벤트가 근거인 관계만 포함한다. 노드·관계 ID를
    # 재사용하므로 별도 그래프 복사 없이 단계 간 공통점과 변화만 비교할 수 있다.
    event_stage = {event.event_id: stage_for_type.get(event.event_type, "기타") for event in ordered_events}
    indexed_edges = list(edges.values())
    stage_graphs = []
    for stage in dict.fromkeys(event_stage.values()):
        stage_edge_indexes = [
            index for index, edge in enumerate(indexed_edges)
            if any(event_stage.get(event_id) == stage for event_id in edge["evidence_event_ids"])
        ]
        stage_node_ids = sorted({
            node_id for index in stage_edge_indexes
            for node_id in (indexed_edges[index]["source"], indexed_edges[index]["target"])
        })
        stage_graphs.append({"stage": stage, "event_count": stage_counts[stage], "node_ids": stage_node_ids, "edge_indexes": stage_edge_indexes})

    # 그래프 재생과 같은 이벤트 ID·관계 인덱스를 재사용하는 포렌식 스윔레인이다.
    # UI는 별도 상관분석 없이 타임라인 점을 클릭해 정확한 그래프 근거로 이동한다.
    lane_for_type = {
        "process_start": "프로세스", "powershell_script": "프로세스",
        "file_create": "파일·지속성", "registry_persistence": "파일·지속성",
        "service_install": "파일·지속성", "scheduled_task": "파일·지속성",
        "wmi_subscription": "파일·지속성", "network_connect": "네트워크·인증",
        "dns_query": "네트워크·인증", "firewall_connection": "네트워크·인증",
        "authentication": "네트워크·인증", "remote_access": "네트워크·인증",
    }
    forensic_items = []
    for event in ordered_events:
        candidate_labels = (
            getattr(event, "process_name", None), getattr(event, "file_path", None),
            getattr(event, "destination_ip", None), getattr(event, "target", None),
            getattr(event, "action", None), event.event_type,
        )
        forensic_items.append({
            "id": event.event_id, "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "lane": lane_for_type.get(event.event_type, "기타"),
            "event_type": event.event_type,
            "label": next(str(value) for value in candidate_labels if value),
            "edge_indexes": [index for index, edge in enumerate(indexed_edges) if event.event_id in edge["evidence_event_ids"]],
            "severity": 0,
        })
    for finding in report.findings:
        related = [event_by_id[event_id] for event_id in finding.event_ids if event_id in event_by_id]
        if related:
            forensic_items.append({
                "id": f"finding:{finding.rule_id}:{finding.event_ids[0]}",
                "event_id": finding.event_ids[0], "timestamp": min(event.timestamp for event in related).isoformat(),
                "lane": "탐지", "event_type": "finding", "label": finding.rule_id,
                "edge_indexes": sorted({index for event_id in finding.event_ids for index, edge in enumerate(indexed_edges) if event_id in edge["evidence_event_ids"]}),
                "severity": finding.severity,
            })
    forensic_items.sort(key=lambda value: (value["timestamp"], value["lane"], value["id"]))
    forensic_timeline = {
        "lanes": ["프로세스", "파일·지속성", "네트워크·인증", "탐지", "기타"],
        "start": ordered_events[0].timestamp.isoformat() if ordered_events else None,
        "end": ordered_events[-1].timestamp.isoformat() if ordered_events else None,
        "items": forensic_items,
    }

    detection_chains = []
    event_types = {event.event_type for event in ordered_events}
    process_text = " ".join(str(getattr(event, "process_name", "") or "") + " " + str(getattr(event, "command_line", "") or "") for event in ordered_events).casefold()
    if any(value in process_text for value in ("powershell", "rundll32", "regsvr32", "mshta", "certutil", "wmic")):
        detection_chains.append({"kind": "LOLBin 문맥", "score": 68, "detail": "관리 도구 실행과 후속 파일·통신을 함께 확인", "event_ids": [event.event_id for event in ordered_events if getattr(event, "process_name", None)]})
    if event_types.intersection({"registry_persistence", "service_install", "scheduled_task", "wmi_subscription"}) and event_types.intersection({"network_connect", "file_create"}):
        detection_chains.append({"kind": "지속성 연쇄", "score": 82, "detail": "지속성 등록 뒤 파일 또는 외부 연결 관찰", "event_ids": [event.event_id for event in ordered_events]})
    if "authentication" in event_types and event_types.intersection({"privilege_use", "remote_access"}):
        detection_chains.append({"kind": "인증 이상", "score": 76, "detail": "로그인과 권한·원격 접근 징후 결합", "event_ids": [event.event_id for event in ordered_events]})
    if event_types.intersection({"dns_query", "network_connect", "firewall_connection"}):
        detection_chains.append({"kind": "DNS·통신 상관", "score": 58, "detail": "프로세스의 이름 조회와 연결 대상을 함께 추적", "event_ids": [event.event_id for event in ordered_events if event.event_type in {"dns_query", "network_connect", "firewall_connection"}]})
    if "usb_device" in event_types or any("onedrive" in str(getattr(event, "file_path", "")).casefold() for event in ordered_events):
        detection_chains.append({"kind": "외부 파일 유입", "score": 61, "detail": "USB·공유·클라우드 동기화 유입 가능성", "event_ids": [event.event_id for event in ordered_events]})
    # 시간 순서와 파일 이름 연결이 필요한 패턴은 별도 모듈에서 계산한다. 기존의
    # 사건 유형 존재 여부 기반 규칙과 구분해 잘못된 단계 결합을 줄인다.
    detection_chains.extend(detect_advanced_chains(ordered_events))
    # API callers may provide only past incidents as the baseline.  The current
    # report must still participate in the comparison, otherwise a real change
    # is silently missed unless callers redundantly include it themselves.
    identity_reports = [report, *(candidate for candidate in baseline_reports if candidate.incident_id != report.incident_id)]
    detection_chains.extend(detect_file_identity_changes(report, identity_reports))
    duplicate_iocs = [{"ioc": ioc, "incident_ids": sorted(ids), "count": len(ids)} for ioc, ids in ioc_incidents.items() if len(ids) > 1 and any(ioc in str(value).casefold() for event in ordered_events for value in (getattr(event, "destination_ip", None), getattr(event, "file_path", None)) if value)]

    current_entities = {value for event in ordered_events for value in (getattr(event, "process_name", None), getattr(event, "destination_ip", None), getattr(event, "file_path", None)) if value}
    comparison = None
    best_overlap: set[str] = set()
    for candidate in baseline_reports:
        if candidate.incident_id == report.incident_id:
            continue
        candidate_entities = {value for event in candidate.source_events for value in (getattr(event, "process_name", None), getattr(event, "destination_ip", None), getattr(event, "file_path", None)) if value}
        overlap = current_entities.intersection(candidate_entities)
        if len(overlap) > len(best_overlap):
            best_overlap = overlap
            comparison = {"incident_id": candidate.incident_id, "shared": sorted(overlap), "added": sorted(current_entities-candidate_entities), "removed": sorted(candidate_entities-current_entities)}

    shadow_rules = [
        {"id": "SHADOW-RARE-PARENT", "would_match": any(edge["rare"] for edge in edges.values()), "impact": "희귀 부모-자식 실행을 검토 필요로 제안"},
        {"id": "SHADOW-DOWNLOAD-CHAIN", "would_match": bool(relation_counts["downloads"]), "impact": "통신 뒤 파일 생성 연쇄를 12점 가중"},
    ]
    test_candidates = [
        {"type": "Sigma", "name": "Process relationship fixture", "safe_event_ids": [event.event_id for event in ordered_events if event.event_type == "process_start"]},
        {"type": "YARA", "name": "File metadata fixture", "safe_event_ids": [event.event_id for event in ordered_events if event.event_type == "file_create"]},
    ]

    node_lookup: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
    for node_id, node in nodes.items():
        node_lookup[("label", node["label"].casefold())].append(node_id)
        if node_id.startswith("file:"):
            node_lookup[("label", node_id.removeprefix("file:").casefold())].append(node_id)
    historical_overlays = historical_subgraph_overlay(report, baseline_reports, node_lookup)
    review_hints = graph_review_hints(nodes, list(edges.values()), attack_paths)
    analysis_metrics = {
        "elapsed_ms": round((perf_counter() - analysis_started) * 1000, 3),
        "event_count": len(ordered_events),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "baseline_incident_count": len(baseline_reports),
    }

    return {
        "nodes": list(nodes.values()), "edges": list(edges.values()),
        "incident_risk_score": report.risk_score,
        "relation_counts": {RELATION_LABELS[key]: value for key, value in relation_counts.items()},
        "rare_relation_count": sum(bool(edge["rare"]) for edge in edges.values()),
        "shortest_path": shortest,
        "shortest_path_labels": [nodes[key]["label"] for key in shortest],
        "hypotheses": hypotheses,
        "missing_evidence": missing,
        "connection_explanations": connection_explanations,
        "hourly_activity": [{"hour": f"{hour:02d}", "count": event_counts[f"{hour:02d}"]} for hour in range(24)],
        "weekly_activity": [{"weekday": day, "hour": hour, "count": weekly_counts[(day, hour)]} for day in range(7) for hour in range(24)],
        "playback": playback, "attack_paths": attack_paths, "common_path_nodes": common_path_nodes,
        "blast_radius": blast_radius, "forensic_timeline": forensic_timeline,
        "clusters": clusters, "baseline": baseline_rows, "adjacency_node_ids": node_ids, "adjacency_matrix": adjacency_matrix,
        "risk_timeline": risk_timeline, "stage_counts": dict(stage_counts), "stage_graphs": stage_graphs, "detection_chains": detection_chains,
        "duplicate_iocs": duplicate_iocs, "comparison": comparison, "shadow_rules": shadow_rules,
        "test_candidates": test_candidates, "historical_overlays": historical_overlays,
        **review_hints, "analysis_metrics": analysis_metrics,
    }


def query_graph(insights: dict[str, object], question: str) -> dict[str, object]:
    """한국어·영문 질의를 로컬에서 관계·노드 조건으로 축약해 검색한다."""
    normalized = question.casefold().strip()
    relation_aliases = {
        "실행": "실행", "생성": "생성", "파일": "파일 생성", "접속": "외부 연결",
        "연결": "외부 연결", "다운로드": "다운로드 추정", "dns": "DNS 조회", "지속성": "지속성 등록",
    }
    requested_relations = {label for token, label in relation_aliases.items() if token in normalized}
    matches = []
    for connection in insights.get("connection_explanations", []):
        haystack = f"{connection['source']} {connection['target']} {connection['why']}".casefold()
        if requested_relations and not any(label.casefold() in haystack for label in requested_relations):
            continue
        terms = [term for term in normalized.replace("에서", " ").replace("까지", " ").split() if len(term) > 1 and term not in relation_aliases]
        if terms and not any(term in haystack for term in terms):
            continue
        matches.append(connection)
    return {
        "question": question, "interpreted_relations": sorted(requested_relations),
        "matches": matches[:30], "matched_node_ids": sorted({node["id"] for node in insights.get("nodes", []) if node["label"].casefold() in normalized}),
        "summary": f"조건에 맞는 관계 {len(matches)}개를 찾았습니다.",
    }
