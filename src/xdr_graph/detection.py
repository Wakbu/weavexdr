from __future__ import annotations

import hashlib
import ipaddress
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from xdr_graph.models import Finding, SecurityEvent, ThreatReference


DEFAULT_RULES_PATH = Path(__file__).parents[2] / "config" / "detection-rules.json"


class ThreatSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: Literal["owasp", "owasp_genai", "mitre_attack", "cisa_kev", "local"]
    version: str = Field(min_length=1)
    retrieved_at: str = Field(min_length=1)
    url: str

    @field_validator("url")
    @classmethod
    def require_https_source(cls, value: str) -> str:
        # 갱신 기준이 평문 전송으로 바뀌면 규칙 공급망이 변조될 수 있으므로 거부한다.
        if not value.startswith("https://"):
            raise ValueError("threat source URL must use HTTPS")
        return value


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["process_start", "file_create", "network_connect"]
    process_names: list[str] = Field(default_factory=list)
    parent_process_names: list[str] = Field(default_factory=list)
    command_contains_any: list[str] = Field(default_factory=list)
    file_extensions: list[str] = Field(default_factory=list)
    path_contains_any: list[str] = Field(default_factory=list)
    destination_scope: Literal["public"] | None = None


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    source: Literal["file", "behavior", "network"]
    severity: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1)
    enabled: bool = True
    match: RuleMatch
    references: list[ThreatReference] = Field(default_factory=list)


class DetectionRuleBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    rule_version: str = Field(min_length=1)
    sources: list[ThreatSource]
    rules: list[DetectionRule]

    @model_validator(mode="after")
    def reject_duplicate_rules(self) -> "DetectionRuleBundle":
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule_id must be unique")
        return self


class RuleBundleManager:
    """검증·체크섬 확인 후에만 규칙 후보를 활성화하고 한 단계 롤백한다."""

    def __init__(self, active_bundle: DetectionRuleBundle) -> None:
        self.active_bundle = active_bundle
        self._previous_bundle: DetectionRuleBundle | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "RuleBundleManager":
        return cls(cls.validate_file(path))

    @staticmethod
    def validate_file(
        path: str | Path, *, expected_sha256: str | None = None
    ) -> DetectionRuleBundle:
        rule_bytes = Path(path).read_bytes()
        if expected_sha256:
            actual_hash = hashlib.sha256(rule_bytes).hexdigest()
            if actual_hash.lower() != expected_sha256.lower():
                raise ValueError("rule bundle SHA-256 mismatch")
        return DetectionRuleBundle.model_validate_json(rule_bytes)

    def activate(self, candidate: DetectionRuleBundle) -> None:
        # 활성본을 덮어쓰기 전에 직전 검증본을 남겨 오탐 급증 시 즉시 복구한다.
        self._previous_bundle = self.active_bundle
        self.active_bundle = candidate

    def rollback(self) -> None:
        if self._previous_bundle is None:
            raise RuntimeError("no previous rule bundle is available")
        self.active_bundle, self._previous_bundle = (
            self._previous_bundle,
            self.active_bundle,
        )


class DetectionRuleEngine:
    """검증된 설정 규칙을 정규화 이벤트에 결정론적으로 적용한다."""

    def __init__(self, bundle: DetectionRuleBundle) -> None:
        self.bundle = bundle

    def analyze(
        self, events: Sequence[SecurityEvent], source: Literal["file", "behavior", "network"]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.bundle.rules:
            if not rule.enabled or rule.source != source:
                continue
            for event in events:
                if self._matches(rule.match, event):
                    findings.append(
                        Finding(
                            source=rule.source,
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            reason=rule.reason,
                            event_ids=[event.event_id],
                            references=rule.references,
                        )
                    )
        return findings

    @staticmethod
    def _matches(match: RuleMatch, event: SecurityEvent) -> bool:
        if event.event_type != match.event_type:
            return False
        process_name = (getattr(event, "process_name", None) or "").lower()
        if match.process_names and process_name not in {
            value.lower() for value in match.process_names
        }:
            return False
        parent_name = (getattr(event, "parent_process", None) or "").lower()
        if match.parent_process_names and parent_name not in {
            value.lower() for value in match.parent_process_names
        }:
            return False
        command_line = (getattr(event, "command_line", None) or "").lower()
        if match.command_contains_any and not any(
            marker.lower() in command_line for marker in match.command_contains_any
        ):
            return False
        file_path = getattr(event, "file_path", None)
        if match.file_extensions and (
            not file_path
            or PureWindowsPath(file_path).suffix.lower()
            not in {value.lower() for value in match.file_extensions}
        ):
            return False
        lowered_path = (file_path or "").lower()
        if match.path_contains_any and not any(
            marker.lower() in lowered_path for marker in match.path_contains_any
        ):
            return False
        if match.destination_scope == "public":
            destination_ip = getattr(event, "destination_ip", None)
            if not destination_ip or not ipaddress.ip_address(destination_ip).is_global:
                return False
        return True


@lru_cache(maxsize=1)
def load_default_detection_engine() -> DetectionRuleEngine:
    bundle = RuleBundleManager.validate_file(DEFAULT_RULES_PATH)
    return DetectionRuleEngine(bundle)
