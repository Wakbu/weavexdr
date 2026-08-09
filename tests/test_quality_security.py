import json
import time
from pathlib import Path

import pytest

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.knowledge_graph import KnowledgeGraphStore
from xdr_graph.release_validation import validate_release_tree
from xdr_graph.runtime_security import PrivilegeBoundary, RuntimeSecrets, validate_configuration
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


PROJECT_ROOT = Path(__file__).parents[1]
SAMPLE_BATCH = PROJECT_ROOT / "samples" / "suspicious_office_batch.json"


def build_report():
    store = SQLiteEventStore(":memory:")
    try:
        raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
        return PersistentIngestionService(store).submit(
            NormalizedEventBatch.model_validate(raw_batch)
        ).report
    finally:
        store.close()


def test_runtime_secrets_are_environment_only_and_fully_redacted(monkeypatch):
    monkeypatch.setenv("WEAVEXDR_API_TOKEN", "a" * 32)
    monkeypatch.setenv("WEAVEXDR_PRIVACY_SALT", "b" * 16)
    secrets = RuntimeSecrets.from_environment()
    assert secrets.redacted() == {"api_token": "<configured>", "privacy_salt": "<configured>"}
    monkeypatch.delenv("WEAVEXDR_PRIVACY_SALT")
    with pytest.raises(ValueError):
        RuntimeSecrets.from_environment()


def test_privileged_actions_require_both_feature_enablement_and_elevation():
    assert PrivilegeBoundary().authorize("terminate_process")[0] is False
    enabled_user = PrivilegeBoundary(active_response_enabled=True)
    assert enabled_user.authorize("terminate_process")[0] is True
    assert enabled_user.authorize("block_network")[0] is False
    enabled_admin = PrivilegeBoundary(active_response_enabled=True, elevated_check=lambda: True)
    assert enabled_admin.authorize("block_network")[0] is True


def test_configuration_and_release_tree_have_no_embedded_secrets():
    assert validate_configuration(PROJECT_ROOT / "config") == []
    assert validate_release_tree(PROJECT_ROOT) == []


def test_repeated_graph_ingestion_stays_bounded_and_fast():
    report = build_report()
    graph = KnowledgeGraphStore(":memory:")
    started = time.perf_counter()
    try:
        for index in range(250):
            graph.ingest_report(report.model_copy(update={"incident_id": f"soak-{index:04d}"}))
        elapsed = time.perf_counter() - started
        assessment = graph.assess_scale()
        # 반복 사건의 공유 엔티티는 중복 노드를 만들지 않아 장기 실행 시 메모리 증가를 제한한다.
        assert assessment.node_count < 300
        assert assessment.edge_count < 2_000
        assert elapsed < 10
    finally:
        graph.close()
