from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from xdr_graph.models import Finding, SecurityEvent, SuppressedFinding


DEFAULT_ALLOWLIST_PATH = Path(__file__).parents[2] / "config" / "allowlist.json"


class AllowlistMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_ids: list[str] = Field(default_factory=list)
    host_ids: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    file_path_prefixes: list[str] = Field(default_factory=list)
    sha256_hashes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_broad_match(self) -> "AllowlistMatch":
        # rule_id만 지정하면 해당 탐지를 모든 장비에서 꺼버릴 수 있다. 호스트,
        # 프로세스, 경로 또는 해시 중 하나를 반드시 함께 요구해 범위를 제한한다.
        selectors = (
            self.host_ids,
            self.process_names,
            self.file_path_prefixes,
            self.sha256_hashes,
        )
        if not any(selectors):
            raise ValueError("allowlist requires at least one event selector")
        return self


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    enabled: bool = False
    reviewer_approved: bool = False
    expires_at: datetime
    match: AllowlistMatch

    @field_validator("expires_at")
    @classmethod
    def require_expiry_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("allowlist expiry must include a timezone offset")
        return value


class AllowlistPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    policy_version: str = Field(min_length=1)
    entries: list[AllowlistEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_duplicate_entries(self) -> "AllowlistPolicy":
        entry_ids = [entry.entry_id for entry in self.entries]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("allowlist entry_id must be unique")
        return self


class AllowlistEngine:
    """승인되고 만료되지 않은 좁은 예외만 탐지 점수에서 제외한다."""

    def __init__(
        self,
        policy: AllowlistPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def apply(
        self, findings: Sequence[Finding], events: Sequence[SecurityEvent]
    ) -> tuple[list[Finding], list[SuppressedFinding]]:
        event_by_id = {event.event_id: event for event in events}
        active_entries = [
            entry
            for entry in self.policy.entries
            if entry.enabled
            and entry.reviewer_approved
            and entry.expires_at.astimezone(timezone.utc) > self._aware_now()
        ]
        remaining: list[Finding] = []
        suppressed: list[SuppressedFinding] = []
        for finding in findings:
            matched_entry = next(
                (
                    entry
                    for entry in active_entries
                    if self._matches_finding(entry, finding, event_by_id)
                ),
                None,
            )
            if matched_entry is None:
                remaining.append(finding)
                continue
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    allowlist_entry_id=matched_entry.entry_id,
                    reason=matched_entry.reason,
                )
            )
        return remaining, suppressed

    @classmethod
    def _matches_finding(
        cls,
        entry: AllowlistEntry,
        finding: Finding,
        event_by_id: dict[str, SecurityEvent],
    ) -> bool:
        match = entry.match
        if match.rule_ids and finding.rule_id not in match.rule_ids:
            return False
        referenced_events = [event_by_id.get(event_id) for event_id in finding.event_ids]
        if not referenced_events or any(event is None for event in referenced_events):
            return False
        # 여러 이벤트를 묶은 상관 탐지는 일부만 정상이어도 전체를 숨기지 않는다.
        return all(cls._matches_event(match, event) for event in referenced_events if event)

    @staticmethod
    def _matches_event(match: AllowlistMatch, event: SecurityEvent) -> bool:
        if match.host_ids and event.host_id.lower() not in {
            value.lower() for value in match.host_ids
        }:
            return False
        process_name = (getattr(event, "process_name", None) or "").lower()
        if match.process_names and process_name not in {
            value.lower() for value in match.process_names
        }:
            return False
        file_path = (getattr(event, "file_path", None) or "").lower()
        if match.file_path_prefixes and not any(
            file_path == prefix.lower().rstrip("\\")
            or file_path.startswith(prefix.lower().rstrip("\\") + "\\")
            for prefix in match.file_path_prefixes
        ):
            return False
        hashes = {
            algorithm.upper(): digest.lower()
            for algorithm, digest in getattr(event, "file_hashes", {}).items()
        }
        if match.sha256_hashes and hashes.get("SHA256") not in {
            digest.lower() for digest in match.sha256_hashes
        }:
            return False
        return True

    def _aware_now(self) -> datetime:
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("allowlist clock must include a timezone offset")
        return current_time.astimezone(timezone.utc)


@lru_cache(maxsize=1)
def load_default_allowlist_engine() -> AllowlistEngine:
    policy = AllowlistPolicy.model_validate_json(
        DEFAULT_ALLOWLIST_PATH.read_text(encoding="utf-8")
    )
    return AllowlistEngine(policy)
