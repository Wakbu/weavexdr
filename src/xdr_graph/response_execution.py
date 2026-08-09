from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from typing import Protocol

from pydantic import BaseModel, Field

from xdr_graph.audit import AuditLogger
from xdr_graph.models import IncidentReport
from xdr_graph.quarantine import QuarantineStore
from xdr_graph.response import (
    ApprovalService,
    BlockNetworkCommand,
    CollectEvidenceCommand,
    DryRunResponseService,
    QuarantineFileCommand,
    ResponseCommand,
    TerminateProcessCommand,
)


class ProcessIdentity(BaseModel):
    process_id: int
    start_time: datetime
    image_path: str


class ProcessController(Protocol):
    def inspect(self, process_id: int) -> ProcessIdentity: ...

    def terminate(self, process_id: int) -> None: ...


class FirewallController(Protocol):
    def block(self, remote_ip: str, command_id: str) -> str: ...

    def unblock(self, rule_name: str) -> None: ...


class ExecutionResult(BaseModel):
    command_id: str
    status: str
    executed: bool
    attempts: int = Field(ge=0)
    resource_id: str | None = None
    error: str | None = None
    recovery_status: str | None = None


def _run_powershell(script: str, variables: dict[str, str], timeout: float = 20) -> str:
    encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command_environment = os.environ.copy()
    for name, value in variables.items():
        command_environment[f"XDR_{name}"] = value
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded_script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=command_environment,
        check=False,
    )
    if completed.returncode != 0:
        error = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        raise RuntimeError(error or f"PowerShell exited with {completed.returncode}")
    return completed.stdout.strip()


class WindowsProcessController:
    _INSPECT_SCRIPT = """
$process = Get-Process -Id ([int]$env:XDR_PID) -ErrorAction Stop
[pscustomobject]@{
    ProcessId = $process.Id
    StartTime = $process.StartTime.ToUniversalTime().ToString('o')
    ImagePath = $process.Path
} | ConvertTo-Json -Compress
"""
    _TERMINATE_SCRIPT = """
Stop-Process -Id ([int]$env:XDR_PID) -Force -ErrorAction Stop
"""

    def inspect(self, process_id: int) -> ProcessIdentity:
        payload = json.loads(
            _run_powershell(self._INSPECT_SCRIPT, {"PID": str(process_id)})
        )
        return ProcessIdentity(
            process_id=payload["ProcessId"],
            start_time=datetime.fromisoformat(payload["StartTime"]),
            image_path=payload["ImagePath"],
        )

    def terminate(self, process_id: int) -> None:
        _run_powershell(self._TERMINATE_SCRIPT, {"PID": str(process_id)})


class WindowsFirewallController:
    _BLOCK_SCRIPT = """
$name = $env:XDR_RULE_NAME
if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $name -Direction Outbound -RemoteAddress $env:XDR_REMOTE_IP -Action Block -ErrorAction Stop | Out-Null
}
$name
"""
    _UNBLOCK_SCRIPT = """
Remove-NetFirewallRule -DisplayName $env:XDR_RULE_NAME -ErrorAction Stop
"""

    def block(self, remote_ip: str, command_id: str) -> str:
        # 사용자 입력을 방화벽 표시 이름으로 직접 쓰지 않고 안정된 해시 ID로 바꾼다.
        suffix = hashlib.sha256(command_id.encode("utf-8")).hexdigest()[:16]
        rule_name = f"WeaveXDR-{suffix}"
        _run_powershell(
            self._BLOCK_SCRIPT,
            {"RULE_NAME": rule_name, "REMOTE_IP": remote_ip},
        )
        return rule_name

    def unblock(self, rule_name: str) -> None:
        _run_powershell(self._UNBLOCK_SCRIPT, {"RULE_NAME": rule_name})


class ActualResponseService:
    """승인과 대상 재검증을 통과한 명령만 제한적으로 실행한다."""

    def __init__(
        self,
        dry_run_service: DryRunResponseService,
        approval_service: ApprovalService,
        audit_log: AuditLogger,
        quarantine_store: QuarantineStore,
        *,
        process_controller: ProcessController | None = None,
        firewall_controller: FirewallController | None = None,
        max_attempts: int = 2,
    ) -> None:
        if max_attempts < 1 or max_attempts > 3:
            raise ValueError("max_attempts must be between 1 and 3")
        self.dry_run_service = dry_run_service
        self.approval_service = approval_service
        self.audit_log = audit_log
        self.quarantine_store = quarantine_store
        self.process_controller = process_controller or WindowsProcessController()
        self.firewall_controller = firewall_controller or WindowsFirewallController()
        self.max_attempts = max_attempts

    def execute(
        self,
        command: ResponseCommand,
        incident_report: IncidentReport,
        *,
        approval_id: str | None = None,
    ) -> ExecutionResult:
        preview = self.dry_run_service.preview(command, incident_report)
        if not preview.allowed:
            return self._blocked(command, "; ".join(preview.reasons))
        if preview.approval_required and (
            not approval_id
            or not self.approval_service.authorize(approval_id, command.command_id)
        ):
            return self._blocked(command, "valid command-bound approval is required")

        self.audit_log.record(
            "response",
            command.action,
            "started",
            {"command_id": command.command_id, "incident_id": command.incident_id},
        )
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                resource_id = self._execute_once(command)
                result = ExecutionResult(
                    command_id=command.command_id,
                    status="succeeded",
                    executed=True,
                    attempts=attempt,
                    resource_id=resource_id,
                )
                self.audit_log.record(
                    "response", command.action, "succeeded", result.model_dump(mode="json")
                )
                return result
            except Exception as error:
                last_error = error
                self.audit_log.record(
                    "response",
                    command.action,
                    "attempt_failed",
                    {
                        "command_id": command.command_id,
                        "attempt": attempt,
                        "error": str(error),
                    },
                )
        result = ExecutionResult(
            command_id=command.command_id,
            status="failed",
            executed=False,
            attempts=self.max_attempts,
            error=str(last_error),
            recovery_status="manual_review_required",
        )
        self.audit_log.record(
            "recovery", command.action, "manual_review_required", result.model_dump(mode="json")
        )
        return result

    def _execute_once(self, command: ResponseCommand) -> str | None:
        if isinstance(command, TerminateProcessCommand):
            identity = self.process_controller.inspect(command.process_id)
            expected_path = str(PureWindowsPath(command.process_image_path)).lower()
            actual_path = str(PureWindowsPath(identity.image_path)).lower()
            time_delta = abs(
                (
                    identity.start_time.astimezone(timezone.utc)
                    - command.process_start_time.astimezone(timezone.utc)
                ).total_seconds()
            )
            if identity.process_id != command.process_id or time_delta > 1 or actual_path != expected_path:
                raise ValueError("process identity changed before response")
            self.process_controller.terminate(command.process_id)
            return str(command.process_id)
        if isinstance(command, QuarantineFileCommand):
            item = self.quarantine_store.quarantine(
                command.file_path,
                expected_sha256=command.sha256,
                command_id=command.command_id,
            )
            return item.item_id
        if isinstance(command, BlockNetworkCommand):
            return self.firewall_controller.block(command.remote_ip, command.command_id)
        if isinstance(command, CollectEvidenceCommand):
            return None
        raise ValueError("unsupported response command")

    def restore_quarantine(self, item_id: str, *, confirmed: bool) -> ExecutionResult:
        if not confirmed:
            raise PermissionError("quarantine restore requires explicit confirmation")
        try:
            item = self.quarantine_store.restore(item_id)
            self.audit_log.record(
                "recovery", "restore_quarantine", "succeeded", item.model_dump(mode="json")
            )
            return ExecutionResult(
                command_id=item.command_id,
                status="restored",
                executed=True,
                attempts=1,
                resource_id=item.item_id,
            )
        except Exception as error:
            self.audit_log.record(
                "recovery", "restore_quarantine", "failed", {"item_id": item_id, "error": str(error)}
            )
            return ExecutionResult(
                command_id="restore",
                status="failed",
                executed=False,
                attempts=1,
                resource_id=item_id,
                error=str(error),
            )

    def remove_network_block(self, rule_name: str, *, confirmed: bool) -> None:
        if not confirmed:
            raise PermissionError("network unblock requires explicit confirmation")
        self.firewall_controller.unblock(rule_name)
        self.audit_log.record(
            "recovery", "unblock_network", "succeeded", {"rule_name": rule_name}
        )

    def _blocked(self, command: ResponseCommand, error: str) -> ExecutionResult:
        result = ExecutionResult(
            command_id=command.command_id,
            status="blocked",
            executed=False,
            attempts=0,
            error=error,
        )
        self.audit_log.record(
            "response", command.action, "blocked", result.model_dump(mode="json")
        )
        return result
