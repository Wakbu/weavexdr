import json
from pathlib import Path

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.knowledge_graph import KnowledgeGraphStore
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def build_report():
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    event_store = SQLiteEventStore(":memory:")
    try:
        return PersistentIngestionService(event_store).submit(
            NormalizedEventBatch.model_validate(raw_batch)
        ).report
    finally:
        event_store.close()


def test_report_conversion_similarity_and_attack_path_queries():
    graph = KnowledgeGraphStore(":memory:", privacy_salt="test-only-salt")
    try:
        first = build_report()
        second = first.model_copy(update={"incident_id": "incident-002"})
        graph.ingest_report(first)
        graph.ingest_report(second)

        similar = graph.find_similar_incidents("incident-001")
        assert similar[0].incident_id == "incident-002"
        assert similar[0].shared_entities >= 4

        alert_id = graph.get_entity_id("Alert", "incident-001")
        file_id = graph.get_entity_id("File", r"c:\users\user\appdata\local\temp\update.exe")
        paths = graph.find_attack_paths(alert_id, file_id)
        assert any(path.relationships == ["OBSERVED", "CREATED"] for path in paths)
    finally:
        graph.close()


def test_graph_rule_links_file_creation_to_public_network_access():
    graph = KnowledgeGraphStore(":memory:")
    try:
        graph.ingest_report(build_report())
        detections = graph.detect_process_file_network_chains("incident-001")
        assert len(detections) == 1
        assert detections[0].rule_id == "GRAPH-PROCESS-FILE-PUBLIC-IP"
        assert len(detections[0].evidence_entities) == 2
    finally:
        graph.close()


def test_personal_scale_assessment_keeps_the_embedded_backend():
    graph = KnowledgeGraphStore(":memory:")
    try:
        graph.ingest_report(build_report())
        assessment = graph.assess_scale()
        assert assessment.node_count >= 5
        assert assessment.edge_count >= 4
        assert assessment.recommended_backend == "sqlite"
        assert assessment.estimated_bytes > 0
    finally:
        graph.close()
