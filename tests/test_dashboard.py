import json
from pathlib import Path

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app, load_dashboard_html, load_world_map_svg
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
        assert 'id="threat-globe"' in dashboard.text
        assert "createThreatGlobe" in dashboard.text
        assert "recentSuspiciousSignals" in dashboard.text
        assert "textureLoaded:Boolean(texture)" in dashboard.text
        assert 'id="globe-window"' in dashboard.text
        assert 'id="globe-detail"' in dashboard.text
        assert "loadGlobeIncidents" in dashboard.text
        assert "date_from:dateFrom" in dashboard.text
        assert "showGlobeSignalList" in dashboard.text
        assert "globeIncidentFilter" in dashboard.text
        assert "Math.log2(item.count+1)" in dashboard.text
        assert "event.target.closest('#globe-detail')" in dashboard.text
        assert "#globe-detail').addEventListener('wheel'" in dashboard.text
        assert "list.onkeydown" in dashboard.text
        assert "globe-detail-list::-webkit-scrollbar-button" in dashboard.text
        assert "grid-auto-rows:max-content" in dashboard.text
        assert "min-height:52px" in dashboard.text
        assert "togglePanelFullscreen" in dashboard.text
        assert "document.fullscreenElement" in dashboard.text
        assert dashboard.text.count("data-fullscreen") >= 6
        assert "textureCanvas.width=2160" in dashboard.text
        assert "latitude=37.57*Math.PI/180" in dashboard.text
        assert "requestAnimationFrame(animate)" not in dashboard.text
        assert "links:links.length" in dashboard.text
        assert "height:clamp(480px,34vw,560px)" in dashboard.text
        assert 'data-tab="graph"' in dashboard.text
        assert "createElementNS" in dashboard.text
        assert "'/collector/configure'" in dashboard.text
        assert "graphViews: new Map()" in dashboard.text
        assert "addEventListener('wheel'" in dashboard.text
        assert "addEventListener('pointerdown'" in dashboard.text
        assert "scheduleIncidentRefresh(JSON.parse(line.slice(5)))" in dashboard.text
        assert 'id="mitre-strip"' in dashboard.text
        assert "graph-search" in dashboard.text
        assert 'id="settings-token"' not in dashboard.text
        assert 'id="modal-token"' not in dashboard.text
        assert "saveToken(" not in dashboard.text
        assert "별도 인증 정보 입력은 필요하지 않습니다" in dashboard.text
        assert '<textarea id="scan-paths"' not in dashboard.text
        assert 'id="scan-files"' in dashboard.text
        assert 'id="scan-folder"' in dashboard.text
        assert 'id="scan-paths-clear"' in dashboard.text
        assert "api('/dialogs/scan-paths'" in dashboard.text
        assert "paths=[...state.scanPaths]" in dashboard.text
        assert "location.host" in dashboard.text
        assert "incidentPageSize: 50" in dashboard.text
        assert "[50,100].forEach" in dashboard.text
        assert ".graph-node:focus-visible rect" in dashboard.text
        assert "api('/incidents?limit=5')" in dashboard.text
        assert "api(`/incidents/stats?${filterParams}`)" in dashboard.text
        assert "incidentPagination(state.incidentStats.filtered_total||0)" in dashboard.text
        assert "scheduleIncidentRefresh" in dashboard.text
        assert "*viewportWidth/rect.width" in dashboard.text
        assert "initialScale=interactive?1" in dashboard.text
        assert "transform.scale=initialScale" in dashboard.text
        assert "분류되지 않은 보안 사건" in dashboard.text
        assert 'rel="icon" href="/assets/weavexdr.svg"' in dashboard.text
        assert 'class="brand-mark" src="/assets/weavexdr.svg"' in dashboard.text
        assert 'id="response-settings"' in dashboard.text
        assert 'id="storage-settings"' in dashboard.text
        assert "api('/storage/health')" in dashboard.text
        assert "'/storage/backup'" in dashboard.text
        assert "response_capabilities" in dashboard.text

        icon = client.get("/assets/weavexdr.svg")
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/svg+xml")
        assert "WeaveXDR" in icon.text
        favicon = client.get("/favicon.ico")
        assert favicon.status_code == 200
        assert favicon.headers["content-type"].startswith("image/x-icon")
        assert len(favicon.content) > 10_000

        assert client.get("/settings").status_code == 401
        settings = client.get("/settings", headers=AUTH).json()
        assert settings["detection_rule_version"]
        assert settings["allowlist_policy_version"]
        assert settings["model"]["fallback"] == "rules"
    finally:
        store.close()


def test_dashboard_exposes_management_and_advanced_graph_controls():
    dashboard = load_dashboard_html()
    for marker in (
        'id="status-filter"', 'id="entity-filter"', 'data-tab="manage"',
        "hierarchical", "radial", "timeline", "force", "graph-minimap",
        "export('svg')", "export('png')", "export('json')",
        "showEntityContextMenu", "ArrowLeft", "delete-demos",
    ):
        assert marker in dashboard


def test_density_modes_and_graph_intelligence_are_semantically_distinct():
    dashboard = load_dashboard_html()
    for marker in (
        ".field-group .column-options input{width:16px", "density-mode-summary",
        'body[data-density="simple"] .incident-table .col-evidence',
        "density-detailed", "graph-insights", "관계 인텔리전스",
        "최단 공격 경로 강조", "showHops", "path-highlight", "inferred",
    ):
        assert marker in dashboard


def test_opqs_features_are_visible_as_dedicated_investigation_tabs():
    dashboard = load_dashboard_html()
    for marker in (
        'data-tab="relations"', 'data-tab="visuals"', 'data-tab="detections"',
        'data-tab="ai-investigation"', "renderRelationsLab", "renderVisualsLab",
        "renderDetectionsLab", "renderAiInvestigationLab", "관계 분석 작업실",
        "시각 분석 보드", "탐지 상관분석 실험실", "AI 조사 데스크",
        "/graph-query", "요일×시간 기준선", "섀도 모드 규칙",
    ):
        assert marker in dashboard


def test_response_workspace_operations_and_fast_start_are_dedicated_surfaces():
    dashboard = load_dashboard_html()
    for marker in (
        'data-nav="response-center"', 'data-nav="workspace"', 'data-nav="operations-lab"',
        'id="page-response-center"', 'id="page-workspace"', 'id="page-operations-lab"',
        "renderResponseCenter", "renderWorkspace", "renderOperationsLab", "toggleCommandPalette",
        "Ctrl+K", "/operations/insights", "/storage/optimize", "/storage/rehearse",
        "deferGlobe:true", "핵심 보호 상태를 확인하고 있습니다.", "weavexdr-high-contrast",
        "pageSize=20", "search-pagination", "unified-result", "profile-option",
        "판정과 위험도만 크게 표시", "response-impact", "04 · 보호 상태",
        'data-nav="hunting"', 'id="page-hunting"', "/hunting/overview",
        "renderHuntingCenter", "runGuidedHunt", "엔터티 위험 분석", "연관 공격 스토리",
        'data-nav="exposure"', 'id="page-exposure"', "/exposure/overview",
        "renderExposureCenter", "renderSoftwarePage", "우선 개선 권고", "최근 30일 공격 표면 신호",
    ):
        assert marker in dashboard


def test_graph_minimap_does_not_cover_interactive_canvas():
    dashboard = load_dashboard_html()
    assert ".attack-graph>.graph-minimap" in dashboard
    assert "pointer-events:none" in dashboard
    assert "container.clientWidth||560" in dashboard
    assert "type-toggle" in dashboard


def test_geo_map_uses_connected_eurasia_and_never_guesses_unknown_country():
    dashboard = load_dashboard_html()
    world_map = load_world_map_svg()
    assert "Natural Earth 국가 경계" in dashboard
    assert "/assets/world-map.svg" in dashboard
    assert "map-leader" in dashboard
    assert "Natural Earth 1:110m" in world_map
    assert "country-kor" in world_map
    assert "country-jpn" in world_map
    assert ".country-kor{" in world_map
    assert ".country-kor,.country-jpn" not in world_map
    assert world_map.count("<path") > 150
    assert "로컬 GeoIP 데이터 필요" in dashboard
    assert "대한민국 · 서울" in dashboard
    assert "x:35+(first*7)%255" not in dashboard
