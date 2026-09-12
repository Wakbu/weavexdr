from datetime import UTC, datetime

from xdr_graph.graph_insights import analyze_graph, compare_response_graph
from xdr_graph.safe_simulation import build_safe_attack_simulation
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


def test_safe_attack_simulation_exercises_visual_investigation_without_side_effects():
    batch = build_safe_attack_simulation(
        now=datetime(2026, 8, 31, 3, 0, tzinfo=UTC), simulation_key="contract"
    )
    assert batch.collector_id == "weavexdr-safe-simulation"
    assert len(batch.events) == 5
    assert {event.event_type for event in batch.events} >= {
        "authentication", "network_connect", "process_start", "file_create", "registry_persistence"
    }
    network = next(event for event in batch.events if event.event_type == "network_connect")
    assert str(network.source_ip) == "203.0.113.77"
    assert str(network.destination_ip) == "192.0.2.10"

    store = SQLiteEventStore(":memory:")
    try:
        report = PersistentIngestionService(store).submit(batch).report
        insight = analyze_graph(report, [report])
        assert report.verdict == "suspicious"
        assert insight["blast_radius"]["entry_node_ids"]
        assert insight["blast_radius"]["target_node_ids"]
        assert insight["blast_radius"]["paths"]
        assert len(insight["forensic_timeline"]["items"]) >= len(batch.events)
        choke = insight["blast_radius"]["choke_points"]
        blocked = choke[0]["node_id"] if choke else next(
            node["id"] for node in insight["nodes"] if node["type"] == "process"
        )
        comparison = compare_response_graph(insight, [blocked])
        assert comparison["after"]["path_count"] < comparison["before"]["path_count"]
        assert comparison["risk_reduction"] > 0
    finally:
        store.close()
