from __future__ import annotations

import operator
from datetime import datetime
from ipaddress import ip_address
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BaseSecurityEvent(BaseModel):
    """모든 수집기가 그래프에 전달해야 하는 공통 이벤트 정보."""

    # 오타나 수집기별 임의 필드를 조용히 허용하면 같은 의미의 필드가 여러
    # 이름으로 쌓일 수 있다. 정규화가 끝난 공통 스키마에서는 알 수 없는
    # 필드를 거부해 수집기 단계에서 계약 위반을 바로 발견한다.
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(min_length=1)
    event_type: str
    timestamp: datetime
    host_id: str = Field(default="local-host", min_length=1)
    source: Literal["sample", "sysmon", "windows_event_log"] = "sample"

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        # 여러 PC의 사건을 시간 순서로 합치려면 로컬 시각만으로는 부족하다.
        # UTC 오프셋이 없는 이벤트는 수집기에서 보정한 뒤 전달하도록 거부한다.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return value

    @field_validator("process_start_time", check_fields=False)
    @classmethod
    def require_process_start_timezone(cls, value: datetime | None) -> datetime | None:
        # PID는 운영체제에서 재사용되므로 프로세스 시작 시각까지 함께 저장한다.
        # 시작 시각이 제공된 경우 공통 사건 시간과 동일하게 시간대를 요구한다.
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("process_start_time must include a timezone offset")
        return value


class ProcessStartEvent(BaseSecurityEvent):
    """프로세스 생성과 부모 관계를 표현하는 정규화 이벤트."""

    event_type: Literal["process_start"]
    process_name: str = Field(min_length=1)
    process_id: int | None = Field(default=None, ge=0)
    process_start_time: datetime | None = None
    # Sysmon ProcessGuid는 PID 재사용과 관계없이 같은 프로세스를 연결하는 기본 키다.
    process_guid: str | None = None
    image_path: str | None = None
    user: str | None = None
    file_hashes: dict[str, str] = Field(default_factory=dict)
    parent_process: str | None = None
    parent_process_id: int | None = Field(default=None, ge=0)
    parent_process_guid: str | None = None
    command_line: str | None = None


class FileCreateEvent(BaseSecurityEvent):
    """프로세스가 파일을 만든 사실을 표현하는 정규화 이벤트."""

    event_type: Literal["file_create"]
    process_name: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    process_start_time: datetime | None = None
    process_guid: str | None = None
    image_path: str | None = None
    user: str | None = None
    file_path: str = Field(min_length=1)


class NetworkConnectEvent(BaseSecurityEvent):
    """프로세스의 외부 또는 내부 네트워크 연결 이벤트."""

    event_type: Literal["network_connect"]
    process_name: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    process_start_time: datetime | None = None
    process_guid: str | None = None
    image_path: str | None = None
    user: str | None = None
    destination_ip: str
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp", "unknown"] = "unknown"

    @field_validator("destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str) -> str:
        # 분석 노드는 이미 정규화된 IP만 받는다. 호스트명 해석이나 잘못된
        # 원문 처리는 향후 수집기에서 담당하고 여기서는 계약을 엄격히 지킨다.
        return str(ip_address(value))


# event_type을 판별자로 사용하면 Pydantic이 필요한 필드를 이벤트 종류별로
# 검사한다. 기존처럼 모든 필드를 Optional로 두었을 때 생기던 불완전 이벤트를 막는다.
SecurityEvent = Annotated[
    ProcessStartEvent | FileCreateEvent | NetworkConnectEvent,
    Field(discriminator="event_type"),
]


class IncidentInput(BaseModel):
    incident_id: str
    events: list[SecurityEvent] = Field(min_length=1)


class Finding(BaseModel):
    source: Literal["file", "behavior", "network"]
    rule_id: str
    severity: int = Field(ge=0, le=100)
    reason: str
    event_ids: list[str] = Field(min_length=1)


class ValidationResult(BaseModel):
    passed: bool
    errors: list[str]
    review_count: int


class IncidentReport(BaseModel):
    incident_id: str
    verdict: Literal["benign", "needs_review", "suspicious"]
    risk_score: int = Field(ge=0, le=100)
    evidence: list[str]
    recommended_actions: list[str]
    validation: ValidationResult


class IncidentState(TypedDict, total=False):
    raw_incident: dict[str, Any]
    incident: IncidentInput
    findings: Annotated[list[Finding], operator.add]
    risk_score: int
    verdict: Literal["benign", "needs_review", "suspicious"]
    evidence: list[str]
    proposed_actions: list[str]
    validation_errors: list[str]
    review_count: int
    report: IncidentReport
