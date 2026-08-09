from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty
from threading import RLock

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field, TypeAdapter

from xdr_graph.models import IncidentReport
from xdr_graph.response import (
    ApprovalRecord,
    ApprovalService,
    DryRunResponseService,
    DryRunResult,
    ResponseCommand,
)
from xdr_graph.response_execution import ActualResponseService, ExecutionResult
from xdr_graph.storage import SQLiteEventStore
from xdr_graph.events import IncidentEventBroker
from xdr_graph.allowlist import load_default_allowlist_engine
from xdr_graph.detection import load_default_detection_engine
from xdr_graph.risk_policy import load_default_risk_policy


_command_adapter = TypeAdapter(ResponseCommand)


class ApprovalRequestBody(BaseModel):
    command_id: str = Field(min_length=1)


class ApprovalDecisionBody(BaseModel):
    approve: bool
    approver: str = Field(min_length=1)


class ExecuteResponseBody(BaseModel):
    approval_id: str | None = None


class RestoreBody(BaseModel):
    confirmed: bool


@dataclass
class ApiRuntime:
    event_store: SQLiteEventStore
    dry_run_service: DryRunResponseService
    approval_service: ApprovalService
    actual_response_service: ActualResponseService | None = None
    event_broker: IncidentEventBroker = field(default_factory=IncidentEventBroker)
    model_status: dict[str, object] = field(
        default_factory=lambda: {"provider": "rule_based", "available": True}
    )
    commands: dict[str, ResponseCommand] = field(default_factory=dict)
    previews: dict[str, DryRunResult] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)


def create_app(
    runtime: ApiRuntime,
    *,
    api_token: str,
    enforce_loopback: bool = True,
) -> FastAPI:
    if len(api_token) < 32:
        raise ValueError("API token must contain at least 32 characters")

    app = FastAPI(title="WeaveXDR Local API", version="0.1.0")

    async def require_local_token(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> None:
        if enforce_loopback:
            client_host = request.client.host if request.client else ""
            if client_host not in {"127.0.0.1", "::1"}:
                raise HTTPException(status_code=403, detail="loopback access only")
        scheme, _, supplied_token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied_token, api_token
        ):
            # 인증 실패에서 토큰 존재 여부나 일부 일치 정보를 노출하지 않는다.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid API credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    protected = [Depends(require_local_token)]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
        return dashboard_path.read_text(encoding="utf-8")

    @app.get("/incidents", response_model=list[IncidentReport], dependencies=protected)
    def list_incidents(limit: int = 100, offset: int = 0):
        try:
            return runtime.event_store.list_incident_reports(limit=limit, offset=offset)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get(
        "/incidents/{incident_id}",
        response_model=IncidentReport,
        dependencies=protected,
    )
    def get_incident(incident_id: str):
        report = runtime.event_store.load_incident_report(incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident was not found")
        return report

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
        }

    @app.get("/events", dependencies=protected)
    def stream_events():
        subscriber = runtime.event_broker.subscribe()

        def event_stream():
            try:
                while True:
                    try:
                        report = subscriber.get(timeout=15)
                        yield f"event: incident\ndata: {report.model_dump_json()}\n\n"
                    except Empty:
                        yield ": heartbeat\n\n"
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
