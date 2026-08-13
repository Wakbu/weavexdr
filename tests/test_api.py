import json
from threading import Event
from pathlib import Path

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.audit import SQLiteAuditLog
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager
from xdr_graph.runtime_health import RuntimeHealthMonitor
from xdr_graph.reporting import IncidentReportExporter
from xdr_graph.self_protection import SelfProtectionMonitor


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
        hunting = client.get("/hunting/overview?window_hours=168", headers=AUTH)
        assert hunting.status_code == 200
        assert hunting.json()["privacy"] == "local_only"
        assert client.get("/hunting/overview?window_hours=2", headers=AUTH).status_code == 422
        exposure = client.get("/exposure/overview", headers=AUTH)
        assert exposure.status_code == 200
        assert exposure.json()["vulnerability_feed"] == "not_configured"
    finally:
        store.close()


def test_local_assistant_receives_minimal_dictionary_incident_context():
    class FakeModelManager:
        def chat(self, question, context):
            payload = json.loads(context)
            assert question == "무엇부터 확인할까?"
            assert payload[0]["incident_id"] == "incident-001"
            assert payload[0]["event_types"]
            return {"answer": "고위험 사건부터 확인하세요.", "provider": "rules", "model": None}

    store = SQLiteEventStore(":memory:")
    PersistentIngestionService(store).submit(
        NormalizedEventBatch.model_validate(json.loads(SAMPLE_BATCH.read_text(encoding="utf-8")))
    )
    runtime = ApiRuntime(event_store=store, dry_run_service=DryRunResponseService(), approval_service=ApprovalService(), model_manager=FakeModelManager())
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        response = client.post("/assistant/chat", headers=AUTH, json={"question": "무엇부터 확인할까?"})
        assert response.status_code == 200
        assert response.json()["provider"] == "rules"
    finally:
        store.close()


def test_incident_graph_insights_api_returns_explainable_analysis():
    client, store = build_client()
    try:
        response = client.get("/incidents/incident-001/graph-insights", headers=AUTH)
        assert response.status_code == 200
        payload = response.json()
        assert payload["edges"]
        assert payload["hypotheses"][0]["evidence_event_ids"]
        assert len(payload["hourly_activity"]) == 24
        assert len(payload["weekly_activity"]) == 168
        query = client.post(
            "/incidents/incident-001/graph-query",
            headers=AUTH,
            json={"question": "powershell 연결"},
        )
        assert query.status_code == 200
        assert "summary" in query.json()
        assert client.get("/incidents/missing/graph-insights", headers=AUTH).status_code == 404
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
        insights = client.get("/operations/insights", headers=AUTH)
        assert insights.status_code == 200
        assert insights.json()["recovery"]["score"] >= 85
        assert client.post("/storage/optimize", headers=AUTH, json={"confirmed": False}).status_code == 403
        assert client.post("/storage/optimize", headers=AUTH, json={"confirmed": True}).json()["integrity_ok"] is True
        rehearsal = client.post("/storage/rehearse", headers=AUTH, json={"confirmed": True})
        assert rehearsal.json()["mode"] == "read_only_rehearsal"
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
        saved = client.post("/saved-searches", headers=AUTH, json={"name": "고위험", "filters": {"window": "168", "risk": "70"}})
        assert saved.status_code == 200
        assert client.get("/saved-searches", headers=AUTH).json()[0]["name"] == "고위험"
        detection = client.post(
            "/custom-detections", headers=AUTH,
            json={"search_id": saved.json()["search_id"], "interval_minutes": 15},
        )
        assert detection.status_code == 200
        assert detection.json()["state"] == "shadow"
        assert detection.json()["last_run_at"]
        detection_id = detection.json()["detection_id"]
        activated = client.post(
            f"/custom-detections/{detection_id}/state", headers=AUTH, json={"state": "active"}
        )
        assert activated.status_code == 200
        assert client.get("/custom-detections", headers=AUTH).json()[0]["state"] == "active"
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


def test_report_integrity_and_update_endpoints(tmp_path):
    client, store = build_client()
    audit = SQLiteAuditLog(":memory:")
    protected = tmp_path / "policy.json"
    protected.write_text('{"enabled": true}', encoding="utf-8")
    integrity = SelfProtectionMonitor(tmp_path / "baseline.json", [protected])
    integrity.initialize()

    class FakeUpdates:
        def status(self):
            return {"state": "idle", "current_version": "20260811.2"}

        def check_latest(self):
            return {"state": "current", "current_version": "20260811.2", "latest_version": "20260811.2"}

        def download_latest(self):
            return {"state": "current", "current_version": "20260811.2"}

    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        audit_log=audit,
        report_exporter=IncidentReportExporter(tmp_path / "reports"),
        self_protection=integrity,
        update_service=FakeUpdates(),
    )
    api_client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        report = api_client.post("/incidents/incident-001/export", headers=AUTH, json={"format": "pdf"})
        assert report.status_code == 200
        assert report.content.startswith(b"%PDF")
        assert len(report.headers["X-WeaveXDR-SHA256"]) == 64
        assert api_client.get("/audit/status", headers=AUTH).json()["integrity_ok"] is True
        assert api_client.get("/security/integrity", headers=AUTH).json()["state"] == "healthy"
        assert api_client.post("/updates/check", headers=AUTH).json()["state"] == "current"
    finally:
        audit.close()
        store.close()
