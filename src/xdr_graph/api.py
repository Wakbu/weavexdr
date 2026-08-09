from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from threading import RLock

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
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
