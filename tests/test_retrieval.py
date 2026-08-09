from datetime import UTC, datetime, timedelta
from pathlib import Path

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.knowledge_graph import KnowledgeGraphStore
from xdr_graph.retrieval import GraphRetrievalExperiment, IncidentMemoryDocument, RetrievalCase
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def sample_report():
    store = SQLiteEventStore(":memory:")
    try:
        batch = NormalizedEventBatch.model_validate_json(SAMPLE_BATCH.read_text(encoding="utf-8"))
        return PersistentIngestionService(store).submit(batch).report
    finally:
        store.close()


def test_graph_retrieval_finds_shared_infrastructure_when_wording_differs():
    graph = KnowledgeGraphStore(":memory:")
    try:
        first = sample_report()
        second = first.model_copy(update={"incident_id": "incident-related"})
        graph.ingest_report(first)
        graph.ingest_report(second)
        experiment = GraphRetrievalExperiment(
            graph,
            [
                IncidentMemoryDocument(incident_id=first.incident_id, summary="encoded office child process"),
                IncidentMemoryDocument(incident_id=second.incident_id, summary="outbound beacon after dropped payload"),
            ],
        )
        result = experiment.compare(
            [RetrievalCase(query="office macro activity", source_incident_id=first.incident_id, expected_incident_id=second.incident_id)]
        )
        assert result.keyword_recall == 0
        assert result.graph_recall == 1
        assert result.recommendation == "use_graph_retrieval_without_llm"
    finally:
        graph.close()


def test_retention_removes_expired_incidents_and_orphaned_entities():
    graph = KnowledgeGraphStore(":memory:")
    try:
        graph.ingest_report(sample_report())
        graph.connection.execute(
            "UPDATE graph_incidents SET observed_at = ?",
            ((datetime.now(UTC) - timedelta(days=100)).isoformat(),),
        )
        graph.connection.commit()
        assert graph.purge_incidents_before(datetime.now(UTC) - timedelta(days=90)) == 1
        assessment = graph.assess_scale()
        assert assessment.node_count == 0
        assert assessment.edge_count == 0
    finally:
        graph.close()
