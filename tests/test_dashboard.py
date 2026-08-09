import json
from pathlib import Path

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.events import IncidentEventBroker
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


TOKEN = "dashboard-token-with-at-least-thirty-two-characters"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def load_sample_batch() -> NormalizedEventBatch:
    return NormalizedEventBatch.model_validate(
        json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    )


def test_broker_keeps_collection_independent_from_slow_dashboard_clients():
    broker = IncidentEventBroker(queue_size=1)
    subscriber = broker.subscribe()
    store = SQLiteEventStore(":memory:")
    try:
        report = PersistentIngestionService(store).submit(load_sample_batch()).report
        broker.publish(report)
        broker.publish(report.model_copy(update={"incident_id": "latest-incident"}))

        # 큐가 가득 차면 오래된 화면 알림만 버리고 최신 보안 사건은 유지한다.
        assert subscriber.get_nowait().incident_id == "latest-incident"
    finally:
        broker.unsubscribe(subscriber)
        store.close()


def test_persistent_ingestion_publishes_a_completed_incident():
    broker = IncidentEventBroker()
    subscriber = broker.subscribe()
    store = SQLiteEventStore(":memory:")
    try:
        receipt = PersistentIngestionService(
            store, event_publisher=broker
        ).submit(load_sample_batch())
        assert subscriber.get_nowait().incident_id == receipt.report.incident_id
    finally:
        broker.unsubscribe(subscriber)
        store.close()


def test_dashboard_and_settings_are_available_without_rendering_event_html():
    store = SQLiteEventStore(":memory:")
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        model_status={"provider": "ollama", "available": False, "fallback": "rules"},
    )
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
        assert "최근 사건" in dashboard.text
        assert "item.textContent=String(text)" in dashboard.text
        assert "row.innerHTML" not in dashboard.text
        assert "location.hash.slice(1)" in dashboard.text
        assert "history.replaceState" in dashboard.text
        assert "fetch('/session'" in dashboard.text
        assert "sessionStorage" not in dashboard.text
        assert 'data-nav="incidents"' in dashboard.text
        assert 'data-nav="investigation"' in dashboard.text
        assert 'id="shutdown"' in dashboard.text
        assert "안전한 데모 생성" in dashboard.text
        assert "new AbortController()" in dashboard.text
        assert "state.streamController?.abort()" in dashboard.text
        assert "clearInterval(state.statusTimer)" in dashboard.text
        assert "if(!badge||!sideStatus)return" in dashboard.text
        assert 'id="overview-topology"' in dashboard.text
        assert 'id="overview-geo"' in dashboard.text
        assert 'data-tab="graph"' in dashboard.text
        assert "createElementNS" in dashboard.text
        assert "'/collector/configure'" in dashboard.text
        assert "graphViews: new Map()" in dashboard.text
        assert "addEventListener('wheel'" in dashboard.text
        assert "addEventListener('pointerdown'" in dashboard.text
        assert "renderIncidentViews({updatedIncidentId:item.incident_id})" in dashboard.text
        assert 'id="mitre-strip"' in dashboard.text
        assert "graph-search" in dashboard.text

        assert client.get("/settings").status_code == 401
        settings = client.get("/settings", headers=AUTH).json()
        assert settings["detection_rule_version"]
        assert settings["allowlist_policy_version"]
        assert settings["model"]["fallback"] == "rules"
    finally:
        store.close()
