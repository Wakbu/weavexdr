import json
from threading import Event
from pathlib import Path

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager
from xdr_graph.runtime_health import RuntimeHealthMonitor


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
        stats = client.get("/incidents/stats", headers=AUTH)
        assert stats.status_code == 200
        assert stats.json()["total"] == 1
        assert stats.json()["filtered_total"] == 1
        assert stats.json()["verdicts"]["suspicious"] == 1
        assert client.get(
            "/incidents/stats?query=does-not-exist", headers=AUTH
        ).json()["filtered_total"] == 0
    finally:
        store.close()


def test_storage_health_and_confirmed_backup_api(tmp_path):
    database = tmp_path / "weavexdr.db"
    store = SQLiteEventStore(database)
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        storage_manager=DatabaseLifecycleManager(database, backup_root=tmp_path / "backups"),
    )
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        health = client.get("/storage/health", headers=AUTH)
        assert health.status_code == 200
        assert health.json()["integrity_ok"] is True
        assert client.post("/storage/backup", headers=AUTH, json={"confirmed": False}).status_code == 403
        backup = client.post("/storage/backup", headers=AUTH, json={"confirmed": True})
        assert backup.status_code == 200
        assert (tmp_path / "backups" / backup.json()["file_name"]).is_file()
        backups = client.get("/storage/backups", headers=AUTH).json()
        assert backups[0]["file_name"] == backup.json()["file_name"]
        assert client.post("/storage/restore", headers=AUTH, json={"file_name": backups[0]["file_name"], "confirmed": False}).status_code == 403
        staged = client.post("/storage/restore", headers=AUTH, json={"file_name": backups[0]["file_name"], "confirmed": True})
        assert staged.status_code == 200
        assert staged.json()["pending_restore"] is True
        assert client.post("/storage/archive", headers=AUTH, json={"confirmed": True}).status_code == 200
    finally:
        store.close()


def test_runtime_resource_health_api(tmp_path):
    store = SQLiteEventStore(":memory:")
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        runtime_monitor=RuntimeHealthMonitor(tmp_path),
    )
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        health = client.get("/runtime/health", headers=AUTH)
        assert health.status_code == 200
        assert health.json()["disk_free_bytes"] > 0
        assert client.get("/status", headers=AUTH).json()["resources"]["memory_bytes"] >= 0
    finally:
        store.close()


def test_authenticated_scan_path_dialog_uses_desktop_picker():
    store = SQLiteEventStore(":memory:")
    selected = [r"C:\사용자\Downloads\sample.exe"]
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        scan_path_picker=lambda kind: selected if kind == "files" else [],
    )
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        assert client.post("/dialogs/scan-paths", json={"kind": "files"}).status_code == 401
        response = client.post("/dialogs/scan-paths", headers=AUTH, json={"kind": "files"})
        assert response.status_code == 200
        assert response.json() == {"paths": selected}
        assert client.post("/dialogs/scan-paths", headers=AUTH, json={"kind": "drive"}).status_code == 422
    finally:
        store.close()


def test_incident_management_workflow_and_advanced_filter():
    client, store = build_client()
    try:
        response = client.patch(
            "/incidents/incident-001/management", headers=AUTH,
            json={"status": "investigating", "note": "PowerShell 조사", "tags": ["powershell"], "bookmarked": True, "checklist": ["서명 확인"], "custom_title": "PowerShell 조사 사건"},
        )
        assert response.status_code == 200
        assert response.json()["management"]["bookmarked"] is True
        filtered = client.get("/incidents?incident_status=investigating&entity=powershell&sort=risk_desc", headers=AUTH)
        assert [item["incident_id"] for item in filtered.json()] == ["incident-001"]
        reset = client.patch(
            "/incidents/incident-001/management", headers=AUTH,
            json={"custom_title": None, "status": "false_positive", "close_reason": "안전한 관리 스크립트", "graph_config": {"layout": "radial", "hiddenTypes": ["file"], "riskOnly": True}},
        )
        assert reset.json()["management"]["custom_title"] is None
        assert reset.json()["management"]["close_reason"]
        assert reset.json()["management"]["graph_config"]["layout"] == "radial"
        feedback = client.get("/feedback/candidates", headers=AUTH).json()
        assert feedback[0]["incident_id"] == "incident-001"
        assert feedback[0]["rule_ids"]
    finally:
        store.close()


def test_demo_cleanup_saved_search_and_merge_split_flow():
    client, store = build_client()
    try:
        first = client.post("/demo/incidents", headers=AUTH).json()
        second = client.post("/demo/incidents", headers=AUTH).json()
        merged = client.post("/incidents/merge", headers=AUTH, json={"incident_ids": [first["incident_id"], second["incident_id"]]})
        assert merged.status_code == 200
        assert merged.json()["management"]["tags"] == ["merged"]
        event_ids = [event["event_id"] for event in merged.json()["source_events"]]
        split = client.post(f"/incidents/{merged.json()['incident_id']}/split", headers=AUTH, json={"event_ids": event_ids[:1]})
        assert split.status_code == 200
        assert len(split.json()) == 2
        assert client.post("/saved-searches", headers=AUTH, json={"name": "고위험", "filters": {"min_risk": 70}}).status_code == 200
        assert client.get("/saved-searches", headers=AUTH).json()[0]["name"] == "고위험"
        assert client.delete("/demo/incidents", headers=AUTH).json()["deleted"] == 2
    finally:
        store.close()


def test_api_token_is_exchanged_for_process_scoped_http_only_session():
    client, store = build_client()
    try:
        assert client.post("/session", json={"token": "wrong-token"}).status_code == 422
        response = client.post("/session", json={"token": TOKEN})
        assert response.json() == {"status": "connected"}
        cookie = response.headers["set-cookie"].lower()
        assert "weavexdr_session=" in cookie
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert client.get("/incidents").status_code == 200
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
        assert client.get(
            "/incidents?verdict=unknown", headers=AUTH
        ).status_code == 422
        assert client.get(
            "/incidents/stats?verdict=unknown", headers=AUTH
        ).status_code == 422
        response = client.post(
            "/responses/preview",
            json={"command_id": "bad", "action": "delete_everything"},
            headers=AUTH,
        )
        assert response.status_code == 422
    finally:
        store.close()


def test_status_and_safe_demo_incident_flow():
    client, store = build_client()
    try:
        status_response = client.get("/status", headers=AUTH)
        assert status_response.status_code == 200
        assert status_response.json()["api"]["state"] == "connected"
        assert status_response.json()["collector"]["state"] == "not_configured"

        demo_response = client.post("/demo/incidents", headers=AUTH)
        assert demo_response.status_code == 200
        demo = demo_response.json()
        assert demo["incident_id"].startswith("demo-incident-")
        assert demo["verdict"] == "suspicious"
        assert len(demo["source_events"]) == 3
        assert client.get(
            f"/incidents/{demo['incident_id']}", headers=AUTH
        ).status_code == 200
    finally:
        store.close()


def test_authenticated_shutdown_runs_the_desktop_callback():
    client, store = build_client()
    stopped = Event()
    # build_client의 앱과 다른 런타임이 필요하므로 종료 콜백이 연결된 전용 앱을 만든다.
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        shutdown_callback=stopped.set,
    )
    shutdown_client = TestClient(
        create_app(runtime, api_token=TOKEN, enforce_loopback=False)
    )
    try:
        assert shutdown_client.post("/shutdown").status_code == 401
        response = shutdown_client.post("/shutdown", headers=AUTH)
        assert response.json() == {"status": "shutting_down"}
        assert stopped.wait(timeout=1)
        assert runtime.shutdown_event.is_set()
    finally:
        store.close()


def test_collector_setup_requires_authentication_and_runs_explicit_callback():
    client, store = build_client()
    requested = Event()
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        collector_setup_callback=requested.set,
    )
    setup_client = TestClient(
        create_app(runtime, api_token=TOKEN, enforce_loopback=False)
    )
    try:
        assert setup_client.post("/collector/configure").status_code == 401
        response = setup_client.post("/collector/configure", headers=AUTH)
        assert response.json() == {"status": "elevation_requested"}
        assert requested.wait(timeout=1)
    finally:
        store.close()
