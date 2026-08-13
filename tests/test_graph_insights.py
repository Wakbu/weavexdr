from xdr_graph.graph_insights import analyze_graph
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
