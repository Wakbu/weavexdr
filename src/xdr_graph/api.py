from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Event, RLock
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import uvicorn
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, TypeAdapter

from xdr_graph.models import IncidentReport
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.response import (
    ApprovalRecord,
    ApprovalService,
    DryRunResponseService,
    DryRunResult,
    ResponseCommand,
)
from xdr_graph.response_execution import ActualResponseService, ExecutionResult, ImpactPreview
from xdr_graph.response_playbook import PlaybookRun, PlaybookSimulation, ResponsePlaybook, ResponsePlaybookService
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import (
    ArchiveInfo,
    BackupInfo,
    DatabaseLifecycleManager,
    RecoveryStatus,
    StorageHealth,
)
from xdr_graph.events import IncidentEventBroker
from xdr_graph.allowlist import load_default_allowlist_engine
from xdr_graph.detection import load_default_detection_engine
from xdr_graph.risk_policy import load_default_risk_policy
from xdr_graph.startup import set_startup_enabled, startup_enabled
from xdr_graph.version import APP_VERSION, BUILD_DATE
from xdr_graph.antivirus import ScanJobManager, ScanPolicy
from xdr_graph.threat_intelligence import ContentUpdateManager, SigmaImporter, ThreatIntelStore
from xdr_graph.runtime_health import RuntimeHealth, RuntimeHealthMonitor
from xdr_graph.audit import SQLiteAuditLog
from xdr_graph.reporting import IncidentReportExporter
from xdr_graph.self_protection import SelfProtectionMonitor
from xdr_graph.update_manager import GitHubUpdateService


_command_adapter = TypeAdapter(ResponseCommand)


def load_dashboard_html() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # PyInstaller one-file 실행 시 소스의 __file__ 위치와 데이터 압축 해제
        # 위치가 달라질 수 있으므로 공식 임시 번들 루트를 기준으로 찾는다.
        dashboard_path = Path(sys._MEIPASS) / "xdr_graph" / "static" / "dashboard.html"
    else:
        dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
    return dashboard_path.read_text(encoding="utf-8")


def load_world_map_svg() -> str:
    """Load the bundled public-domain Natural Earth map in source and EXE layouts."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        map_path = Path(sys._MEIPASS) / "xdr_graph" / "static" / "world-map.svg"
    else:
        map_path = Path(__file__).parent / "static" / "world-map.svg"
    return map_path.read_text(encoding="utf-8")


def load_brand_icon_svg() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        icon_path = Path(sys._MEIPASS) / "xdr_graph" / "static" / "weavexdr.svg"
    else:
        icon_path = Path(__file__).parent / "static" / "weavexdr.svg"
    return icon_path.read_text(encoding="utf-8")


def load_brand_icon_ico() -> bytes:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        icon_path = Path(sys._MEIPASS) / "xdr_graph" / "static" / "weavexdr.ico"
    else:
        icon_path = Path(__file__).parent / "static" / "weavexdr.ico"
    return icon_path.read_bytes()


class ApprovalRequestBody(BaseModel):
    command_id: str = Field(min_length=1)


class ApprovalDecisionBody(BaseModel):
    approve: bool
    approver: str = Field(min_length=1)


class ExecuteResponseBody(BaseModel):
    approval_id: str | None = None


class RestoreBody(BaseModel):
    confirmed: bool


class PlaybookRequestBody(BaseModel):
    playbook: ResponsePlaybook
    approvals: dict[str, str] = Field(default_factory=dict)


class BackupBody(BaseModel):
    confirmed: bool


class DatabaseRestoreBody(BaseModel):
    file_name: str = Field(min_length=1, max_length=260)
    confirmed: bool


class SessionTokenBody(BaseModel):
    token: str = Field(min_length=32)


class IncidentManagementBody(BaseModel):
    status: str | None = None
    note: str | None = Field(default=None, max_length=10000)
    tags: list[str] | None = None
    bookmarked: bool | None = None
    checklist: list[str] | None = None
    custom_title: str | None = Field(default=None, max_length=200)
    close_reason: str | None = Field(default=None, max_length=1000)
    archived_at: str | None = None
    graph_config: dict[str, object] | None = None


class StartupBody(BaseModel):
    enabled: bool


class ScanRequestBody(BaseModel):
    paths: list[str] = Field(default_factory=list, max_length=50)
    profile: str = "custom"


class ScanPathDialogBody(BaseModel):
    kind: Literal["files", "folder"]


class ScanPolicyBody(BaseModel):
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    excluded_signers: list[str] = Field(default_factory=list, max_length=100)
    excluded_hashes: list[str] = Field(default_factory=list, max_length=100)


class ContentImportBody(BaseModel):
    source: str
    path: str = Field(min_length=1)
    expected_sha256: str | None = None


class StixImportBody(BaseModel):
    path: str = Field(min_length=1)
    source: str = Field(default="stix", min_length=1)


class ReportExportBody(BaseModel):
    format: Literal["html", "pdf", "csv", "json", "stix", "evidence"]
    redact: bool = True
    include_notes: bool = True


class SigmaImportBody(BaseModel):
    payload: str = Field(min_length=1, max_length=5_000_000)


class SavedSearchBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    filters: dict[str, object]


class DeleteIncidentBody(BaseModel):
    confirmation: str


class MergeIncidentsBody(BaseModel):
    incident_ids: list[str] = Field(min_length=2, max_length=20)


class SplitIncidentBody(BaseModel):
    event_ids: list[str] = Field(min_length=1)


@dataclass
class ApiRuntime:
    event_store: SQLiteEventStore
    dry_run_service: DryRunResponseService
    approval_service: ApprovalService
    actual_response_service: ActualResponseService | None = None
    playbook_service: ResponsePlaybookService | None = None
    storage_manager: DatabaseLifecycleManager | None = None
    runtime_monitor: RuntimeHealthMonitor | None = None
    recovery_state: dict[str, object] = field(default_factory=dict)
    scan_manager: ScanJobManager | None = None
    threat_intel_store: ThreatIntelStore | None = None
    content_manager: ContentUpdateManager | None = None
    audit_log: SQLiteAuditLog | None = None
    report_exporter: IncidentReportExporter | None = None
    self_protection: SelfProtectionMonitor | None = None
    update_service: GitHubUpdateService | None = None
    event_broker: IncidentEventBroker = field(default_factory=IncidentEventBroker)
    model_status: dict[str, object] = field(
        default_factory=lambda: {"provider": "rule_based", "available": True}
    )
    collector_status: dict[str, object] = field(
        default_factory=lambda: {
            "state": "not_configured",
            "label": "실시간 수집기 미구성",
            "sources": [],
        }
    )
    collector_setup_callback: Callable[[], None] | None = None
    shutdown_callback: Callable[[], None] | None = None
    open_dashboard_callback: Callable[[], None] | None = None
    collector_pause_callback: Callable[[bool], None] | None = None
    scan_path_picker: Callable[[str], list[str]] | None = None
    instance_token: str | None = None
    instance_port: int | None = None
    lifecycle_state: str = "starting"
    shutdown_event: Event = field(default_factory=Event)
    commands: dict[str, ResponseCommand] = field(default_factory=dict)
    previews: dict[str, DryRunResult] = field(default_factory=dict)
    instance_nonces: dict[str, float] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)


def create_app(
    runtime: ApiRuntime,
    *,
    api_token: str,
    enforce_loopback: bool = True,
) -> FastAPI:
    if len(api_token) < 32:
        raise ValueError("API token must contain at least 32 characters")

    # 서버 시작 시 정적 자원을 먼저 읽어 EXE 번들 누락을 브라우저의 늦은 500
    # 오류가 아니라 시작/릴리스 검증 단계에서 발견한다.
    dashboard_html = load_dashboard_html()
    world_map_svg = load_world_map_svg()
    brand_icon_svg = load_brand_icon_svg()
    brand_icon_ico = load_brand_icon_ico()
    app = FastAPI(title="WeaveXDR Local API", version=APP_VERSION)
    # 브라우저에는 API 토큰 원문 대신 이 프로세스에서만 유효한 별도 세션 값을
    # HttpOnly 쿠키로 전달한다. 서버 재시작 시 자동 폐기되어 고정 API 토큰도 노출하지 않는다.
    browser_session_token = secrets.token_urlsafe(32)

    @app.middleware("http")
    async def add_local_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(Exception)
    async def log_unhandled_error(request: Request, error: Exception) -> JSONResponse:
        # 창 없는 EXE에서도 원인을 확인할 수 있도록 모든 미처리 서버 예외를
        # 회전 로그에 남긴다. 응답에는 내부 경로나 비밀 값을 노출하지 않는다.
        logging.getLogger("weavexdr").exception(
            "unhandled API error on %s", request.url.path, exc_info=error
        )
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    def require_loopback(request: Request) -> None:
        if enforce_loopback:
            client_host = request.client.host if request.client else ""
            if client_host not in {"127.0.0.1", "::1"}:
                raise HTTPException(status_code=403, detail="loopback access only")
            host_name = urlsplit("//" + request.headers.get("host", "")).hostname
            if host_name not in {"127.0.0.1", "::1", "localhost"}:
                raise HTTPException(status_code=400, detail="invalid local host header")

    async def require_local_token(
        request: Request,
        authorization: str | None = Header(default=None),
        browser_session: str | None = Cookie(
            default=None,
            alias="weavexdr_session",
        ),
    ) -> None:
        require_loopback(request)
        scheme, _, supplied_token = (authorization or "").partition(" ")
        valid_bearer = scheme.lower() == "bearer" and hmac.compare_digest(
            supplied_token,
            api_token,
        )
        valid_session = bool(browser_session) and hmac.compare_digest(
            browser_session or "",
            browser_session_token,
        )
        if not valid_bearer and not valid_session:
            # 인증 실패에서 토큰 존재 여부나 일부 일치 정보를 노출하지 않는다.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid API credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if enforce_loopback and valid_session and request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = urlsplit(request.headers.get("origin", ""))
            request_host = urlsplit("//" + request.headers.get("host", ""))
            if (
                origin.scheme != "http"
                or origin.hostname != request_host.hostname
                or (origin.port or 80) != (request_host.port or 80)
            ):
                raise HTTPException(status_code=403, detail="same-origin request required")

    protected = [Depends(require_local_token)]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        # 명시적인 응답 객체를 사용해 번들 환경에서 문자열 응답 모델 추론을 거치지 않는다.
        return HTMLResponse(content=dashboard_html)

    @app.get("/assets/world-map.svg", include_in_schema=False)
    def world_map_asset() -> Response:
        return Response(
            content=world_map_svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/assets/weavexdr.svg", include_in_schema=False)
    def brand_icon_asset() -> Response:
        return Response(
            content=brand_icon_svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon_asset() -> Response:
        return Response(
            content=brand_icon_ico,
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.post("/session")
    def create_browser_session(
        body: SessionTokenBody,
        request: Request,
        response: Response,
    ) -> dict[str, str]:
        require_loopback(request)
        if not hmac.compare_digest(body.token, api_token):
            raise HTTPException(status_code=401, detail="invalid API credentials")
        response.set_cookie(
            "weavexdr_session",
            browser_session_token,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return {"status": "connected"}

    @app.post("/instance/open")
    def reopen_existing_instance(request: Request):
        require_loopback(request)
        timestamp = request.headers.get("X-WeaveXDR-Timestamp", "")
        nonce = request.headers.get("X-WeaveXDR-Nonce", "")
        supplied = request.headers.get("X-WeaveXDR-Signature", "")
        try:
            issued_at = int(timestamp)
        except ValueError:
            issued_at = 0
        signed = f"{os.getpid()}:{runtime.instance_port}:{APP_VERSION}:{timestamp}:{nonce}".encode()
        expected = hmac.new((runtime.instance_token or "").encode(), signed, "sha256").hexdigest()
        now = time.time()
        with runtime.lock:
            runtime.instance_nonces = {
                value: seen for value, seen in runtime.instance_nonces.items() if now - seen <= 30
            }
            replayed = nonce in runtime.instance_nonces
            if nonce and not replayed:
                runtime.instance_nonces[nonce] = now
        if (
            not runtime.instance_token
            or not nonce
            or abs(now - issued_at) > 15
            or replayed
            or not hmac.compare_digest(supplied, expected)
        ):
            raise HTTPException(status_code=401, detail="invalid instance handshake")
        if runtime.open_dashboard_callback:
            runtime.open_dashboard_callback()
        return {"pid": os.getpid(), "port": runtime.instance_port, "version": APP_VERSION}

    @app.get("/incidents", dependencies=protected)
    def list_incidents(
        limit: int = 100,
        offset: int = 0,
        verdict: str | None = None,
        query: str | None = None,
        incident_status: str | None = None,
        min_risk: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        entity: str | None = None,
        sort: str = "updated_desc",
    ):
        try:
            return runtime.event_store.list_incident_views(
                limit=limit, offset=offset, verdict=verdict, query=query,
                status=incident_status, min_risk=min_risk, date_from=date_from,
                date_to=date_to, entity=entity, sort=sort,
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get("/incidents/stats", dependencies=protected)
    def incident_stats(verdict: str | None = None, query: str | None = None,
                       incident_status: str | None = None, min_risk: int | None = None,
                       date_from: str | None = None, date_to: str | None = None,
                       entity: str | None = None, sort: str | None = None):
        try:
            result = runtime.event_store.incident_stats()
            result["filtered_total"] = runtime.event_store.filtered_incident_count(
                verdict=verdict, query=query, status=incident_status, min_risk=min_risk,
                date_from=date_from, date_to=date_to, entity=entity,
            )
            return result
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get(
        "/incidents/{incident_id}",
        dependencies=protected,
    )
    def get_incident(incident_id: str):
        report = runtime.event_store.load_incident_view(incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        return report

    @app.post("/incidents/{incident_id}/export", dependencies=protected)
    def export_incident(incident_id: str, body: ReportExportBody):
        if runtime.report_exporter is None:
            raise HTTPException(status_code=503, detail="incident reporting is unavailable")
        report = runtime.event_store.load_incident_report(incident_id)
        view = runtime.event_store.load_incident_view(incident_id)
        if report is None or view is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        audit_records = [record for record in runtime.audit_log.list_records() if record.details.get("incident_id") == incident_id] if runtime.audit_log else []
        try:
            artifact = runtime.report_exporter.export(report, dict(view["management"]), body.format, audit_records=audit_records, redact=body.redact, include_notes=body.include_notes)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        response = FileResponse(artifact.path, media_type=artifact.media_type, filename=artifact.path.name)
        response.headers["X-WeaveXDR-SHA256"] = artifact.sha256
        return response

    @app.patch("/incidents/{incident_id}/management", dependencies=protected)
    def update_incident_management(incident_id: str, body: IncidentManagementBody):
        changes = body.model_dump(exclude_unset=True)
        try:
            return runtime.event_store.update_incident_management(incident_id, changes)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="incident was not found") from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.delete("/incidents/{incident_id}", status_code=204, dependencies=protected)
    def permanently_delete_incident(incident_id: str, body: DeleteIncidentBody):
        # 삭제 대상 ID를 정확히 다시 입력해야만 원본 이벤트까지 제거한다.
        if body.confirmation != incident_id:
            raise HTTPException(status_code=409, detail="incident confirmation does not match")
        if not runtime.event_store.delete_incident(incident_id):
            raise HTTPException(status_code=404, detail="incident was not found")
        return Response(status_code=204)

    @app.delete("/demo/incidents", dependencies=protected)
    def delete_demo_incidents():
        return {"deleted": runtime.event_store.delete_demo_incidents()}

    @app.post("/incidents/merge", dependencies=protected)
    def merge_incidents(body: MergeIncidentsBody):
        reports = [runtime.event_store.load_incident_report(value) for value in body.incident_ids]
        if any(report is None for report in reports):
            raise HTTPException(status_code=404, detail="one or more incidents were not found")
        valid_reports = [report for report in reports if report is not None]
        severity = {"benign": 0, "needs_review": 1, "suspicious": 2}
        template = max(valid_reports, key=lambda report: severity[report.verdict])
        events = {event.event_id: event for report in valid_reports for event in report.source_events}
        findings = {(finding.rule_id, tuple(finding.event_ids)): finding for report in valid_reports for finding in report.findings}
        merged = template.model_copy(update={
            "incident_id": f"merged-{uuid4().hex[:12]}",
            "risk_score": max(report.risk_score for report in valid_reports),
            "evidence": list(dict.fromkeys(value for report in valid_reports for value in report.evidence)),
            "recommended_actions": list(dict.fromkeys(value for report in valid_reports for value in report.recommended_actions)),
            "findings": list(findings.values()), "source_events": list(events.values()),
            "attack_chains": [chain for report in valid_reports for chain in report.attack_chains],
        })
        runtime.event_store.save_manual_incident(merged)
        runtime.event_store.update_incident_management(merged.incident_id, {"tags": ["merged"], "note": f"{len(valid_reports)}개 사건 병합"})
        return runtime.event_store.load_incident_view(merged.incident_id)

    @app.post("/incidents/{incident_id}/split", dependencies=protected)
    def split_incident(incident_id: str, body: SplitIncidentBody):
        report = runtime.event_store.load_incident_report(incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        selected = set(body.event_ids)
        left = [event for event in report.source_events if event.event_id in selected]
        right = [event for event in report.source_events if event.event_id not in selected]
        if not left or not right:
            raise HTTPException(status_code=422, detail="split must leave events on both sides")
        results = []
        for suffix, events in (("a", left), ("b", right)):
            event_ids = {event.event_id for event in events}
            split = report.model_copy(update={
                "incident_id": f"split-{uuid4().hex[:10]}-{suffix}",
                "source_events": events,
                "findings": [finding for finding in report.findings if event_ids.intersection(finding.event_ids)],
                "attack_chains": [],
            })
            runtime.event_store.save_manual_incident(split)
            runtime.event_store.update_incident_management(split.incident_id, {"tags": ["split"], "note": f"{incident_id} 분리 결과"})
            results.append(runtime.event_store.load_incident_view(split.incident_id))
        return results

    @app.get("/incidents/{incident_id}/related", dependencies=protected)
    def related_incidents(incident_id: str):
        source = runtime.event_store.load_incident_report(incident_id)
        if source is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        needles = {str(value) for event in source.source_events for value in (
            event.host_id, getattr(event, "process_name", None), getattr(event, "user", None),
            getattr(event, "destination_ip", None), getattr(event, "file_path", None),
        ) if value}
        matches = []
        for candidate in runtime.event_store.list_incident_views(limit=500):
            if candidate["incident_id"] == incident_id:
                continue
            haystack = json.dumps(candidate, ensure_ascii=False)
            overlap = [value for value in needles if value in haystack]
            if overlap:
                matches.append({"incident_id": candidate["incident_id"], "shared_entities": overlap[:5], "impact_count": len(overlap)})
        return matches[:20]

    @app.get("/saved-searches", dependencies=protected)
    def saved_searches():
        return runtime.event_store.list_saved_searches()

    @app.get("/feedback/candidates", dependencies=protected)
    def feedback_candidates():
        return runtime.event_store.list_feedback_candidates()

    @app.post("/saved-searches", dependencies=protected)
    def save_search(body: SavedSearchBody):
        return runtime.event_store.save_search(body.name, body.filters)

    @app.delete("/saved-searches/{search_id}", status_code=204, dependencies=protected)
    def delete_search(search_id: int):
        if not runtime.event_store.delete_saved_search(search_id):
            raise HTTPException(status_code=404, detail="saved search was not found")
        return Response(status_code=204)

    @app.get("/settings", dependencies=protected)
    def settings():
        rules = load_default_detection_engine().bundle
        risk = load_default_risk_policy()
        allowlist = load_default_allowlist_engine().policy
        return {
            "detection_rule_version": rules.rule_version,
            "risk_policy_version": risk.policy_version,
            "allowlist_policy_version": allowlist.policy_version,
            "allowlist_entries": [entry.model_dump(mode="json") for entry in allowlist.entries],
            "model": runtime.model_status,
            "application": {"version": APP_VERSION, "build_date": BUILD_DATE},
            "startup_enabled": startup_enabled(),
        }

    @app.get("/status", dependencies=protected)
    def runtime_status():
        with runtime.lock:
            collector_status = dict(runtime.collector_status)
        collector_delay: float | None = None
        if collector_status.get("last_event_at"):
            try:
                last_event = datetime.fromisoformat(str(collector_status["last_event_at"]))
                collector_delay = max(0.0, (datetime.now(UTC) - last_event.astimezone(UTC)).total_seconds())
            except (TypeError, ValueError):
                collector_delay = None
        resources = runtime.runtime_monitor.sample(collector_delay_seconds=collector_delay) if runtime.runtime_monitor else None
        return {
            "api": {"state": "connected", "label": "로컬 API 정상"},
            "collector": collector_status,
            "model": runtime.model_status,
            "active_response": runtime.actual_response_service is not None,
            "response_capabilities": {
                "process_tree": runtime.actual_response_service is not None,
                "reversible_actions": ["quarantine_file", "block_network"],
                "playbooks": runtime.playbook_service is not None,
                "approval_required": True,
            },
            "lifecycle": runtime.lifecycle_state,
            "resources": resources,
            "recovery": runtime.recovery_state,
            "security": {
                "session": "httponly_samesite_strict",
                "same_origin_mutations": True,
                "instance_handshake": "hmac_sha256_nonce_dpapi",
                "data_acl": "current_user_and_system",
                "audit_integrity": runtime.audit_log.verify_integrity() if runtime.audit_log else None,
                "self_protection": runtime.self_protection.verify().state if runtime.self_protection else "unavailable",
            },
            "application": {"version": APP_VERSION, "build_date": BUILD_DATE, "pid": os.getpid(), "port": runtime.instance_port},
        }

    @app.get("/audit/status", dependencies=protected)
    def audit_status():
        if runtime.audit_log is None:
            raise HTTPException(status_code=503, detail="audit log is unavailable")
        records = runtime.audit_log.list_records()
        return {"integrity_ok": runtime.audit_log.verify_integrity(), "records": len(records), "latest": records[-1] if records else None}

    @app.get("/security/integrity", dependencies=protected)
    def self_integrity():
        if runtime.self_protection is None:
            raise HTTPException(status_code=503, detail="self protection is unavailable")
        return runtime.self_protection.as_payload(runtime.self_protection.verify())

    @app.get("/updates/status", dependencies=protected)
    def update_status():
        if runtime.update_service is None:
            raise HTTPException(status_code=503, detail="update service is unavailable")
        return runtime.update_service.status()

    @app.post("/updates/check", dependencies=protected)
    def check_updates():
        if runtime.update_service is None:
            raise HTTPException(status_code=503, detail="update service is unavailable")
        return runtime.update_service.check_latest()

    @app.post("/updates/download", dependencies=protected)
    def download_update():
        if runtime.update_service is None:
            raise HTTPException(status_code=503, detail="update service is unavailable")
        return runtime.update_service.download_latest()

    @app.get("/runtime/health", response_model=RuntimeHealth, dependencies=protected)
    def runtime_health():
        if runtime.runtime_monitor is None:
            raise HTTPException(status_code=503, detail="runtime monitoring is unavailable")
        return runtime.runtime_monitor.sample()

    @app.post("/scans", dependencies=protected)
    def start_scan(body: ScanRequestBody):
        if runtime.scan_manager is None:
            raise HTTPException(status_code=503, detail="file scanner is unavailable")
        if body.profile not in {"quick", "full", "custom"}:
            raise HTTPException(status_code=422, detail="unknown scan profile")
        if body.profile == "custom" and not body.paths:
            raise HTTPException(status_code=422, detail="custom scan requires paths")
        try:
            return runtime.scan_manager.start(body.paths, profile=body.profile)
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/dialogs/scan-paths", dependencies=protected)
    def choose_scan_paths(body: ScanPathDialogBody):
        if runtime.scan_path_picker is None:
            raise HTTPException(status_code=503, detail="native path selection is unavailable")
        try:
            return {"paths": runtime.scan_path_picker(body.kind)}
        except (RuntimeError, ValueError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/scans/{job_id}", dependencies=protected)
    def get_scan(job_id: str):
        if runtime.scan_manager is None:
            raise HTTPException(status_code=503, detail="file scanner is unavailable")
        try:
            return runtime.scan_manager.get(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="scan was not found") from error

    @app.post("/scans/{job_id}/cancel", dependencies=protected)
    def cancel_scan(job_id: str):
        if runtime.scan_manager is None:
            raise HTTPException(status_code=503, detail="file scanner is unavailable")
        try:
            return runtime.scan_manager.cancel(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="scan was not found") from error

    @app.put("/settings/scan-policy", dependencies=protected)
    def update_scan_policy(body: ScanPolicyBody):
        if runtime.scan_manager is None:
            raise HTTPException(status_code=503, detail="file scanner is unavailable")
        # 예외는 해시·서명자·절대 경로만 허용하고 UI가 위험 경고를 표시할 수 있게 그대로 반환한다.
        policy = runtime.scan_manager.scanner.policy.model_copy(update=body.model_dump())
        runtime.scan_manager.scanner.policy = ScanPolicy.model_validate(policy)
        return {"policy": runtime.scan_manager.scanner.policy, "warning": "scan exclusions can reduce protection"}

    @app.get("/quarantine", dependencies=protected)
    def list_quarantine():
        if runtime.actual_response_service is None:
            return []
        return runtime.actual_response_service.quarantine_store.list_items()

    @app.post("/threat-intel/stix/import", dependencies=protected)
    def import_stix(body: StixImportBody):
        if runtime.threat_intel_store is None:
            raise HTTPException(status_code=503, detail="threat intelligence store is unavailable")
        path = Path(body.path).resolve(strict=True)
        return {"imported": runtime.threat_intel_store.import_stix(path.read_bytes(), source=body.source)}

    @app.post("/content/import", dependencies=protected)
    def import_content(body: ContentImportBody):
        if runtime.content_manager is None:
            raise HTTPException(status_code=503, detail="content manager is unavailable")
        return runtime.content_manager.activate_file(body.source, body.path, expected_sha256=body.expected_sha256)

    @app.post("/sigma/import", dependencies=protected)
    def import_sigma(body: SigmaImportBody):
        rules = SigmaImporter().parse(body.payload)
        return {"rules": [rule.model_dump(mode="json") for rule in rules], "enabled": 0}

    @app.put("/settings/startup", dependencies=protected)
    def update_startup(body: StartupBody):
        try:
            return {"enabled": set_startup_enabled(body.enabled)}
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

    @app.post("/collector/pause", dependencies=protected)
    def pause_collector():
        if runtime.collector_pause_callback is None:
            raise HTTPException(status_code=503, detail="collector control is unavailable")
        runtime.collector_pause_callback(True)
        return {"status": "paused"}

    @app.post("/collector/resume", dependencies=protected)
    def resume_collector():
        if runtime.collector_pause_callback is None:
            raise HTTPException(status_code=503, detail="collector control is unavailable")
        runtime.collector_pause_callback(False)
        return {"status": "running"}

    @app.post("/collector/configure", dependencies=protected)
    def configure_collector():
        if runtime.collector_setup_callback is None:
            raise HTTPException(status_code=503, detail="collector setup is unavailable")
        # 관리자 권한 상승은 서버가 몰래 수행하지 않고 사용자가 대시보드에서
        # 명시적으로 누른 뒤 Windows UAC 확인창을 통해 승인하도록 한다.
        runtime.collector_setup_callback()
        return {"status": "elevation_requested"}

    @app.post(
        "/demo/incidents",
        response_model=IncidentReport,
        dependencies=protected,
    )
    def create_demo_incident():
        # 실제 악성 파일이나 명령을 실행하지 않고 정규화 이벤트만 만들어 전체
        # 탐지·상관분석·저장·화면 흐름을 사용자가 안전하게 체험하게 한다.
        now = datetime.now(UTC)
        demo_key = uuid4().hex[:12]
        process_start = now.isoformat()
        batch = NormalizedEventBatch.model_validate(
            {
                "schema_version": "1.0",
                "batch_id": f"demo-batch-{demo_key}",
                "incident_id": f"demo-incident-{demo_key}",
                "collector_id": "weavexdr-safe-demo",
                "received_at": (now + timedelta(seconds=4)).isoformat(),
                "events": [
                    {
                        "event_id": f"demo-process-{demo_key}",
                        "event_type": "process_start",
                        "timestamp": process_start,
                        "host_id": "local-demo-host",
                        "source": "sample",
                        "process_name": "powershell.exe",
                        "process_id": 4242,
                        "process_start_time": process_start,
                        "parent_process": "WINWORD.EXE",
                        "command_line": "powershell.exe -enc SAFE_DEMO_ONLY",
                    },
                    {
                        "event_id": f"demo-file-{demo_key}",
                        "event_type": "file_create",
                        "timestamp": (now + timedelta(seconds=2)).isoformat(),
                        "host_id": "local-demo-host",
                        "source": "sample",
                        "process_name": "powershell.exe",
                        "process_id": 4242,
                        "process_start_time": process_start,
                        "file_path": r"C:\Users\Demo\AppData\Local\Temp\update.exe",
                    },
                    {
                        "event_id": f"demo-network-{demo_key}",
                        "event_type": "network_connect",
                        "timestamp": (now + timedelta(seconds=3)).isoformat(),
                        "host_id": "local-demo-host",
                        "source": "sample",
                        "process_name": "powershell.exe",
                        "process_id": 4242,
                        "process_start_time": process_start,
                        "destination_ip": "8.8.8.8",
                        "destination_port": 443,
                        "protocol": "tcp",
                    },
                ],
            }
        )
        receipt = PersistentIngestionService(
            runtime.event_store,
            event_publisher=runtime.event_broker,
        ).submit(batch)
        runtime.event_store.update_incident_management(
            receipt.report.incident_id, {"tags": ["demo"], "note": "안전한 합성 텔레메트리 사건"}
        )
        return receipt.report

    @app.post("/shutdown", dependencies=protected)
    def shutdown(response: Response):
        if runtime.shutdown_callback is None:
            raise HTTPException(status_code=503, detail="desktop shutdown is unavailable")
        # Uvicorn은 현재 응답을 마친 뒤 should_exit를 확인한다. 번들 환경에서
        # background task 실행이 늦어지는 경우를 피하려고 플래그를 즉시 설정한다.
        # 모든 브라우저 탭의 스트리밍 응답을 먼저 끝내야 Uvicorn이 활성 연결을
        # 기다리지 않고 실제 EXE 프로세스까지 종료할 수 있다.
        runtime.shutdown_event.set()
        runtime.lifecycle_state = "stopping"
        runtime.shutdown_callback()
        response.delete_cookie("weavexdr_session", path="/")
        return {"status": "shutting_down"}

    @app.get("/events", dependencies=protected)
    def stream_events():
        subscriber = runtime.event_broker.subscribe()

        def event_stream():
            next_heartbeat = time.monotonic() + 15
            try:
                while not runtime.shutdown_event.is_set():
                    try:
                        report = subscriber.get(timeout=0.25)
                        yield f"event: incident\ndata: {report.model_dump_json()}\n\n"
                    except Empty:
                        if time.monotonic() >= next_heartbeat:
                            yield ": heartbeat\n\n"
                            next_heartbeat = time.monotonic() + 15
            finally:
                runtime.event_broker.unsubscribe(subscriber)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.post("/responses/preview", response_model=DryRunResult, dependencies=protected)
    def preview_response(payload: dict):
        try:
            command = _command_adapter.validate_python(payload)
        except Exception as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        report = runtime.event_store.load_incident_report(command.incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        preview = runtime.dry_run_service.preview(command, report)
        with runtime.lock:
            runtime.commands[command.command_id] = command
            runtime.previews[command.command_id] = preview
        return preview

    @app.post("/responses/impact", response_model=ImpactPreview, dependencies=protected)
    def preview_response_impact(payload: dict):
        if runtime.actual_response_service is None:
            raise HTTPException(status_code=503, detail="active response is disabled")
        try:
            command = _command_adapter.validate_python(payload)
        except Exception as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        report = runtime.event_store.load_incident_report(command.incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        return runtime.actual_response_service.preview_impact(command, report)

    @app.post("/approvals", response_model=ApprovalRecord, dependencies=protected)
    def request_approval(body: ApprovalRequestBody):
        with runtime.lock:
            preview = runtime.previews.get(body.command_id)
        if preview is None:
            raise HTTPException(status_code=404, detail="response preview was not found")
        try:
            return runtime.approval_service.request(preview)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post(
        "/approvals/{approval_id}/decision",
        response_model=ApprovalRecord,
        dependencies=protected,
    )
    def decide_approval(approval_id: str, body: ApprovalDecisionBody):
        try:
            return runtime.approval_service.decide(
                approval_id, approve=body.approve, approver=body.approver
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post(
        "/responses/{command_id}/execute",
        response_model=ExecutionResult,
        dependencies=protected,
    )
    def execute_response(command_id: str, body: ExecuteResponseBody):
        if runtime.actual_response_service is None:
            raise HTTPException(status_code=503, detail="active response is disabled")
        with runtime.lock:
            command = runtime.commands.get(command_id)
        if command is None:
            raise HTTPException(status_code=404, detail="response command was not found")
        report = runtime.event_store.load_incident_report(command.incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        return runtime.actual_response_service.execute(
            command, report, approval_id=body.approval_id
        )

    @app.post(
        "/quarantine/{item_id}/restore",
        response_model=ExecutionResult,
        dependencies=protected,
    )
    def restore_quarantine(item_id: str, body: RestoreBody):
        if runtime.actual_response_service is None:
            raise HTTPException(status_code=503, detail="active response is disabled")
        try:
            return runtime.actual_response_service.restore_quarantine(
                item_id, confirmed=body.confirmed
            )
        except PermissionError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error

    @app.get("/responses/recoveries", dependencies=protected)
    def list_response_recoveries():
        if runtime.actual_response_service is None:
            return []
        return runtime.actual_response_service.list_recoveries()

    @app.post("/responses/{command_id}/undo", response_model=ExecutionResult, dependencies=protected)
    def undo_response(command_id: str, body: RestoreBody):
        if runtime.actual_response_service is None:
            raise HTTPException(status_code=503, detail="active response is disabled")
        try:
            return runtime.actual_response_service.undo(command_id, confirmed=body.confirmed)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except PermissionError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/playbooks/simulate", response_model=PlaybookSimulation, dependencies=protected)
    def simulate_playbook(body: PlaybookRequestBody):
        if runtime.playbook_service is None:
            raise HTTPException(status_code=503, detail="response playbooks are disabled")
        report = runtime.event_store.load_incident_report(body.playbook.incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        try:
            return runtime.playbook_service.simulate(body.playbook, report)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.post("/playbooks/execute", response_model=PlaybookRun, dependencies=protected)
    def execute_playbook(body: PlaybookRequestBody):
        if runtime.playbook_service is None:
            raise HTTPException(status_code=503, detail="response playbooks are disabled")
        report = runtime.event_store.load_incident_report(body.playbook.incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        return runtime.playbook_service.execute(body.playbook, report, approvals=body.approvals)

    @app.get("/storage/health", response_model=StorageHealth, dependencies=protected)
    def storage_health():
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        return runtime.storage_manager.health()

    @app.post("/storage/backup", dependencies=protected)
    def backup_storage(body: BackupBody):
        if not body.confirmed:
            raise HTTPException(status_code=403, detail="database backup requires confirmation")
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        path = runtime.storage_manager.backup()
        return {"status": "created", "file_name": path.name}

    @app.get("/storage/backups", response_model=list[BackupInfo], dependencies=protected)
    def list_storage_backups():
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        return runtime.storage_manager.list_backups()

    @app.get("/storage/recovery", response_model=RecoveryStatus, dependencies=protected)
    def storage_recovery_status():
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        return runtime.storage_manager.recovery_status()

    @app.post("/storage/restore", response_model=RecoveryStatus, dependencies=protected)
    def stage_storage_restore(body: DatabaseRestoreBody):
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        try:
            return runtime.storage_manager.stage_restore(body.file_name, confirmed=body.confirmed)
        except PermissionError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except (FileNotFoundError, ValueError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/storage/archive", response_model=ArchiveInfo, dependencies=protected)
    def archive_expired_storage(body: BackupBody):
        if not body.confirmed:
            raise HTTPException(status_code=403, detail="database archive requires confirmation")
        if runtime.storage_manager is None:
            raise HTTPException(status_code=503, detail="storage maintenance is unavailable")
        return runtime.storage_manager.archive_expired()

    @app.get("/quarantine/{item_id}/restore-preview", dependencies=protected)
    def preview_quarantine_restore(item_id: str):
        if runtime.actual_response_service is None or runtime.scan_manager is None:
            raise HTTPException(status_code=503, detail="quarantine rescan is unavailable")
        try:
            item = runtime.actual_response_service.quarantine_store.get(item_id)
            inspection = runtime.scan_manager.scanner.inspect(
                item.quarantine_path, event_id=f"restore-preview-{item_id}", use_cache=False
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail="quarantine item was not found") from error
        return {"item": item, "inspection": inspection, "restore_recommended": not inspection.findings}

    return app


def main() -> None:
    token = os.environ.get("WEAVEXDR_API_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("WEAVEXDR_API_TOKEN must be set to at least 32 characters")
    store = SQLiteEventStore("data/xdr.db")
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
    )
    # 기본 바인딩을 loopback으로 고정한다. 외부 공개는 별도 인증·TLS 설계 없이는 허용하지 않는다.
    uvicorn.run(create_app(runtime, api_token=token), host="127.0.0.1", port=8765)


if __name__ == "__main__":
    main()
