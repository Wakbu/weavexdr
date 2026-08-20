from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from xdr_graph.response_playbook import ResponsePlaybook


# API 경계 검증 모델은 라우팅 코드와 분리한다. 새 요청 필드가 추가되어도
# 서버 수명 주기나 서비스 조립 코드에 손대지 않고 계약만 검토할 수 있다.
class ApprovalRequestBody(BaseModel):
    command_id: str = Field(min_length=1)


class ApprovalDecisionBody(BaseModel):
    approve: bool
    approver: str = Field(min_length=1)


class ExecuteResponseBody(BaseModel):
    approval_id: str | None = None


class RestoreBody(BaseModel):
    confirmed: bool


class UpdateApplyBody(BaseModel):
    confirmed: bool


class ModelSelectionBody(BaseModel):
    model: str = Field(min_length=1, max_length=80)


class AssistantQuestionBody(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    incident_id: str | None = Field(default=None, max_length=160)


class GraphQueryBody(BaseModel):
    question: str = Field(min_length=1, max_length=500)


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


class CustomDetectionBody(BaseModel):
    search_id: int = Field(gt=0)
    interval_minutes: Literal[15, 30, 60, 180, 360, 720, 1440] = 60


class CustomDetectionStateBody(BaseModel):
    state: Literal["shadow", "active", "paused"]


class DeleteIncidentBody(BaseModel):
    confirmation: str


class MergeIncidentsBody(BaseModel):
    incident_ids: list[str] = Field(min_length=2, max_length=20)


class SplitIncidentBody(BaseModel):
    event_ids: list[str] = Field(min_length=1)
