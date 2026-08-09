import json
from pathlib import Path

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


TOKEN = "test-token-with-at-least-thirty-two-characters"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def build_client():
    store = SQLiteEventStore(":memory:")
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    PersistentIngestionService(store).submit(
        NormalizedEventBatch.model_validate(raw_batch)
    )
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
    )
    return TestClient(
        create_app(runtime, api_token=TOKEN, enforce_loopback=False)
    ), store


def test_health_is_public_but_incidents_require_a_valid_token():
    client, store = build_client()
    try:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/incidents").status_code == 401
        assert client.get(
            "/incidents", headers={"Authorization": "Bearer wrong-token"}
        ).status_code == 401
        response = client.get("/incidents", headers=AUTH)
        assert response.status_code == 200
        assert response.json()[0]["incident_id"] == "incident-001"
    finally:
        store.close()


def test_incident_detail_exposes_score_findings_and_source_events():
    client, store = build_client()
    try:
        response = client.get("/incidents/incident-001", headers=AUTH)
        body = response.json()
        assert response.status_code == 200
        assert body["risk_score"] == 100
        assert body["findings"]
        assert body["attack_chains"]
        assert len(body["source_events"]) == 3
        assert client.get("/incidents/missing", headers=AUTH).status_code == 404
    finally:
        store.close()


def test_response_preview_approval_and_rejection_api_flow():
    client, store = build_client()
    try:
        command = {
            "command_id": "api-terminate",
            "incident_id": "incident-001",
            "action": "terminate_process",
            "requested_at": "2026-08-09T01:00:00+00:00",
            "process_id": 4242,
            "process_start_time": "2026-08-09T01:00:00+00:00",
            "process_image_path": "C:\\Tools\\powershell.exe",
        }
        preview = client.post("/responses/preview", json=command, headers=AUTH)
        assert preview.status_code == 200
        assert preview.json()["allowed"] is True
        approval = client.post(
            "/approvals", json={"command_id": "api-terminate"}, headers=AUTH
        )
        assert approval.status_code == 200
        approval_id = approval.json()["approval_id"]
        decision = client.post(
            f"/approvals/{approval_id}/decision",
            json={"approve": False, "approver": "local-user"},
            headers=AUTH,
        )
        assert decision.json()["status"] == "rejected"
        assert client.post(
            "/responses/api-terminate/execute",
            json={"approval_id": approval_id},
            headers=AUTH,
        ).status_code == 503
    finally:
        store.close()


def test_invalid_pagination_and_command_schema_are_rejected():
    client, store = build_client()
    try:
        assert client.get("/incidents?limit=9999", headers=AUTH).status_code == 422
        response = client.post(
            "/responses/preview",
            json={"command_id": "bad", "action": "delete_everything"},
            headers=AUTH,
        )
        assert response.status_code == 422
    finally:
        store.close()
