from xdr_graph.graph_insights import analyze_graph, query_graph
from xdr_graph.models import IncidentReport


def test_graph_insights_explain_relationships_paths_and_hypotheses():
    report = IncidentReport.model_validate({
        "incident_id": "graph-001", "verdict": "suspicious", "risk_score": 82,
        "evidence": [], "recommended_actions": [],
        "validation": {"passed": True, "errors": [], "review_count": 0},
        "source_events": [
            {"event_id": "p1", "event_type": "process_start", "timestamp": "2026-08-13T01:00:00+09:00", "process_name": "powershell.exe", "process_guid": "proc-1", "parent_process": "winword.exe"},
            {"event_id": "n1", "event_type": "network_connect", "timestamp": "2026-08-13T01:01:00+09:00", "process_name": "powershell.exe", "process_guid": "proc-1", "destination_ip": "8.8.8.8", "destination_port": 443, "protocol": "tcp"},
            {"event_id": "f1", "event_type": "file_create", "timestamp": "2026-08-13T01:02:00+09:00", "process_name": "powershell.exe", "process_guid": "proc-1", "file_path": "C:\\Temp\\payload.exe"},
        ],
    })
    result = analyze_graph(report, [report])
    assert result["edges"]
    assert result["relation_counts"]["파일 생성"] >= 1
    assert result["relation_counts"]["외부 연결"] >= 1
    assert result["relation_counts"]["다운로드 추정"] >= 1
    assert any(edge["inferred"] for edge in result["edges"])
    assert result["shortest_path_labels"]
    assert result["hypotheses"][0]["evidence_event_ids"]
    assert result["connection_explanations"][0]["evidence_event_ids"]
    assert len(result["hourly_activity"]) == 24
    assert len(result["weekly_activity"]) == 168
    assert result["playback"][-1]["visible_edges"]
    assert len(result["adjacency_matrix"]) == len(result["adjacency_node_ids"])
    assert result["risk_timeline"][-1]["risk"] >= 0
    assert result["clusters"]
    assert result["detection_chains"]
    query = query_graph(result, "powershell 연결")
    assert query["matches"]
    assert query["matches"][0]["evidence_event_ids"]


def _report(incident_id: str, events: list[dict]) -> IncidentReport:
    return IncidentReport.model_validate({
        "incident_id": incident_id, "verdict": "suspicious", "risk_score": 80,
        "evidence": [], "recommended_actions": [],
        "validation": {"passed": True, "errors": [], "review_count": 0},
        "source_events": events,
    })


def test_graph_insights_detects_advanced_chains_and_identity_change():
    current = _report("current", [
        {"event_id": "download", "event_type": "network_connect", "timestamp": "2026-08-20T00:59:00+09:00", "process_name": "powershell.exe", "process_guid": "download-proc", "destination_ip": "8.8.8.8"},
        {"event_id": "archive", "event_type": "file_create", "timestamp": "2026-08-20T01:00:00+09:00", "process_name": "powershell.exe", "process_guid": "download-proc", "file_path": r"C:\Temp\drop.zip"},
        {"event_id": "payload", "event_type": "file_create", "timestamp": "2026-08-20T01:01:00+09:00", "file_path": r"C:\Temp\payload.exe"},
        {"event_id": "execute", "event_type": "process_start", "timestamp": "2026-08-20T01:02:00+09:00", "process_name": "payload.exe", "image_path": r"C:\Temp\payload.exe", "file_hashes": {"sha256": "new"}, "file_signer": "New Publisher"},
        {"event_id": "persist", "event_type": "registry_persistence", "timestamp": "2026-08-20T01:03:00+09:00", "windows_event_id": 13, "channel": "Sysmon", "action": "set", "target": "Run"},
        {"event_id": "share", "event_type": "file_create", "timestamp": "2026-08-20T01:04:00+09:00", "file_path": r"\\server\share\remote.exe"},
        {"event_id": "share-run", "event_type": "process_start", "timestamp": "2026-08-20T01:05:00+09:00", "process_name": "remote.exe", "image_path": r"\\server\share\remote.exe"},
    ])
    past = _report("past", [
        {"event_id": "old-execute", "event_type": "process_start", "timestamp": "2026-08-19T01:00:00+09:00", "process_name": "payload.exe", "image_path": r"C:\Windows\payload.exe", "file_hashes": {"sha256": "old"}, "file_signer": "Old Publisher"},
    ])

    result = analyze_graph(current, [past])
    kinds = {chain["kind"] for chain in result["detection_chains"]}
    assert {"다운로드·압축 해제·실행·지속성", "네트워크 공유 파일 유입", "파일 신원 연쇄 변경"} <= kinds
    identity = next(chain for chain in result["detection_chains"] if chain["kind"] == "파일 신원 연쇄 변경")
    assert {"경로", "해시", "서명자"} <= set(identity["changed_fields"])
    assert {"execute", "old-execute"} <= set(identity["event_ids"])
    assert result["analysis_metrics"]["event_count"] == 7
    assert result["analysis_metrics"]["elapsed_ms"] >= 0


def test_graph_insights_returns_historical_overlay_noise_and_merge_hints():
    current = _report("current", [
        {"event_id": "p1", "event_type": "process_start", "timestamp": "2026-08-20T02:00:00+09:00", "process_name": "same.exe", "process_guid": "guid-1", "image_path": r"C:\Tools\same.exe"},
        {"event_id": "p2", "event_type": "process_start", "timestamp": "2026-08-20T02:01:00+09:00", "process_name": "same.exe", "process_guid": "guid-2", "image_path": r"C:\Tools\same.exe"},
        {"event_id": "quiet", "event_type": "file_create", "timestamp": "2026-08-20T02:02:00+09:00", "file_path": r"C:\Temp\quiet.txt"},
    ])
    past = _report("past", [
        {"event_id": "old", "event_type": "process_start", "timestamp": "2026-08-19T02:00:00+09:00", "process_name": "same.exe", "image_path": r"C:\Tools\same.exe"},
    ])

    result = analyze_graph(current, [past])
    assert result["historical_overlays"][0]["incident_id"] == "past"
    assert result["historical_overlays"][0]["node_ids"]
    assert result["merge_suggestions"][0]["label"] == "same.exe"
    assert set(result["core_node_ids"]).isdisjoint(result["noise_node_ids"])
