from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Annotated, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from xdr_graph.models import IncidentReport


_packaged_config = Path(__file__).parent / "config"
_source_config = Path(__file__).parents[2] / "config"
DEFAULT_RESPONSE_POLICY_PATH = (_packaged_config if _packaged_config.is_dir() else _source_config) / "response-policy.json"
ResponseAction = Literal[
    "terminate_process", "quarantine_file", "block_network", "collect_additional_evidence"
]


class BaseResponseCommand(BaseModel):
    """W10에서는 실행 모드를 dry_run으로 고정해 실제 시스템 변경을 차단한다."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    command_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    action: ResponseAction
    requested_at: datetime
    execution_mode: Literal["dry_run"] = "dry_run"

    @field_validator("requested_at")
    @classmethod
    def require_requested_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("response request time must include a timezone offset")
        return value


class TerminateProcessCommand(BaseResponseCommand):
    action: Literal["terminate_process"]
    process_id: int = Field(ge=1)
    process_start_time: datetime
    process_image_path: str = Field(min_length=1)

    @field_validator("process_start_time")
    @classmethod
    def require_start_timezone(cls, value: datetime) -> datetime:
        # PID는 재사용되므로 실제 대응 전 생성 시각까지 일치해야 같은 프로세스로 본다.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("process start time must include a timezone offset")
        return value


class QuarantineFileCommand(BaseResponseCommand):
    action: Literal["quarantine_file"]
    file_path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")


class CollectEvidenceCommand(BaseResponseCommand):
    action: Literal["collect_additional_evidence"]
    event_ids: list[str] = Field(min_length=1)


class BlockNetworkCommand(BaseResponseCommand):
    action: Literal["block_network"]
    remote_ip: str | None = None
    remote_domain: str | None = Field(default=None, pattern=r"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$", max_length=253)
    program_path: str | None = None
    duration_minutes: int = Field(default=60, ge=1, le=10080)

    @field_validator("remote_ip")
    @classmethod
    def require_ip_address(cls, value: str | None) -> str | None:
        from ipaddress import ip_address

        return str(ip_address(value)) if value else None

    @model_validator(mode="after")
    def require_one_network_target(self) -> "BlockNetworkCommand":
        targets = [self.remote_ip, self.remote_domain, self.program_path]
        if sum(value is not None for value in targets) != 1:
            raise ValueError("exactly one network target is required")
        return self


ResponseCommand = Annotated[
    TerminateProcessCommand
    | QuarantineFileCommand
    | BlockNetworkCommand
    | CollectEvidenceCommand,
    Field(discriminator="action"),
]


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    policy_version: str = Field(min_length=1)
    allowed_actions: list[ResponseAction]
    approval_required_actions: list[ResponseAction]
    approval_ttl_minutes: int = Field(ge=1, le=60)
    protected_process_names: list[str]
    protected_path_prefixes: list[str]

    @model_validator(mode="after")
    def validate_action_sets(self) -> "ResponsePolicy":
        if not set(self.approval_required_actions) <= set(self.allowed_actions):
            raise ValueError("approval actions must be included in allowed_actions")
        return self


class DryRunResult(BaseModel):
    command_id: str
    action: ResponseAction
    allowed: bool
    executed: Literal[False] = False
    approval_required: bool
    reasons: list[str]
    target_summary: str
    impact_scope: list[str] = Field(default_factory=list)
    reversible: bool = False


class ApprovalRecord(BaseModel):
    approval_id: str
    command_id: str
    status: Literal["pending", "approved", "rejected", "expired"]
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    approver: str | None = None


class DryRunResponseService:
    """대응 가능 여부만 계산하고 운영체제 명령은 절대 호출하지 않는다."""

    def __init__(self, policy: ResponsePolicy | None = None) -> None:
        self.policy = policy or load_default_response_policy()

    def preview(
        self, command: ResponseCommand, incident_report: IncidentReport
    ) -> DryRunResult:
        reasons: list[str] = []
        if command.action not in self.policy.allowed_actions:
            reasons.append("action is not allowed by response policy")
        if command.incident_id != incident_report.incident_id:
            reasons.append("command incident does not match report incident")
        if command.action not in incident_report.recommended_actions:
            reasons.append("action was not recommended by the verified incident report")

        if isinstance(command, TerminateProcessCommand):
            process_name = PureWindowsPath(command.process_image_path).name.lower()
            if process_name in {name.lower() for name in self.policy.protected_process_names}:
                reasons.append("target is a protected system process")
            target_summary = (
                f"process pid={command.process_id} start={command.process_start_time.isoformat()} "
                f"image={command.process_image_path}"
            )
        elif isinstance(command, QuarantineFileCommand):
            if self._is_protected_path(command.file_path):
                reasons.append("target is under a protected system path")
            target_summary = f"file path={command.file_path} sha256={command.sha256.lower()}"
        elif isinstance(command, BlockNetworkCommand):
            target_type, target = (
                ("remote_ip", command.remote_ip)
                if command.remote_ip
                else ("remote_domain", command.remote_domain)
                if command.remote_domain
                else ("program", command.program_path)
            )
            target_summary = (
                f"{target_type}={target} direction=outbound "
                f"expires_in={command.duration_minutes}m"
            )
        else:
            report_event_ids = {event.event_id for event in incident_report.source_events}
            if not set(command.event_ids) <= report_event_ids:
                reasons.append("evidence request references an event outside the incident")
            target_summary = f"events={','.join(command.event_ids)}"

        return DryRunResult(
            command_id=command.command_id,
            action=command.action,
            allowed=not reasons,
            approval_required=command.action in self.policy.approval_required_actions,
            reasons=reasons or ["dry-run validation passed; no system change was performed"],
            target_summary=target_summary,
            reversible=isinstance(command, (QuarantineFileCommand, BlockNetworkCommand)),
        )

    def _is_protected_path(self, file_path: str) -> bool:
        normalized_path = str(PureWindowsPath(file_path)).lower().rstrip("\\")
        for protected_prefix in self.policy.protected_path_prefixes:
            normalized_prefix = str(PureWindowsPath(protected_prefix)).lower().rstrip("\\")
            if normalized_path == normalized_prefix or normalized_path.startswith(
                normalized_prefix + "\\"
            ):
                return True
        return False


class ApprovalService:
    """dry-run이 통과한 위험 조치에 명시적인 사용자 결정을 연결한다."""

    def __init__(
        self,
        policy: ResponsePolicy | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy or load_default_response_policy()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._records: dict[str, ApprovalRecord] = {}

    def request(self, preview: DryRunResult) -> ApprovalRecord:
        if not preview.allowed:
            raise ValueError("blocked dry-run cannot request approval")
        current_time = self._aware_now()
        if not preview.approval_required:
            record = ApprovalRecord(
                approval_id=f"approval-{uuid4()}",
                command_id=preview.command_id,
                status="approved",
                requested_at=current_time,
                expires_at=current_time
                + timedelta(minutes=self.policy.approval_ttl_minutes),
                decided_at=current_time,
                approver="policy:no-approval-required",
            )
            self._records[record.approval_id] = record
            return record
        record = ApprovalRecord(
            approval_id=f"approval-{uuid4()}",
            command_id=preview.command_id,
            status="pending",
            requested_at=current_time,
            expires_at=current_time + timedelta(minutes=self.policy.approval_ttl_minutes),
        )
        self._records[record.approval_id] = record
        return record

    def decide(
        self, approval_id: str, *, approve: bool, approver: str
    ) -> ApprovalRecord:
        if not approver.strip():
            raise ValueError("approver is required")
        record = self._current_record(approval_id)
        if record.status != "pending":
            raise ValueError(f"approval is already {record.status}")
        decided = record.model_copy(
            update={
                "status": "approved" if approve else "rejected",
                "decided_at": self._aware_now(),
                "approver": approver,
            }
        )
        self._records[approval_id] = decided
        return decided

    def authorize(self, approval_id: str, command_id: str) -> bool:
        record = self._current_record(approval_id)
        return record.command_id == command_id and record.status == "approved"

    def _current_record(self, approval_id: str) -> ApprovalRecord:
        if approval_id not in self._records:
            raise KeyError("approval record was not found")
        record = self._records[approval_id]
        if record.status in {"pending", "approved"} and self._aware_now() >= record.expires_at:
            record = record.model_copy(update={"status": "expired"})
            self._records[approval_id] = record
        return record

    def _aware_now(self) -> datetime:
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("approval clock must include a timezone offset")
        return current_time.astimezone(timezone.utc)


@lru_cache(maxsize=1)
def load_default_response_policy() -> ResponsePolicy:
    return ResponsePolicy.model_validate_json(
        DEFAULT_RESPONSE_POLICY_PATH.read_text(encoding="utf-8")
    )
