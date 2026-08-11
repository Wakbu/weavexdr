from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Callable, Literal, Protocol

from pydantic import BaseModel, Field

from xdr_graph.audit import AuditLogger
from xdr_graph.models import IncidentReport
from xdr_graph.quarantine import QuarantineStore
from xdr_graph.response import (
    ApprovalService,
    BlockNetworkCommand,
    CollectEvidenceCommand,
    DryRunResponseService,
    DryRunResult,
    QuarantineFileCommand,
    ResponseCommand,
    TerminateProcessCommand,
)


class ProcessIdentity(BaseModel):
    process_id: int
    start_time: datetime
    image_path: str


class ImpactPreview(BaseModel):
    command_id: str
    allowed: bool
    target_summary: str
    affected_resources: list[str] = Field(default_factory=list)
    protected_resources: list[str] = Field(default_factory=list)
    reversible: bool = False


class RecoveryAction(BaseModel):
    command_id: str
    kind: Literal["quarantine", "network_block"]
    resource_id: str
    created_at: datetime
    expires_at: datetime | None = None
    active: bool = True


class ProcessController(Protocol):
    def inspect(self, process_id: int) -> ProcessIdentity: ...

    def terminate(self, process_id: int) -> None: ...


class FirewallController(Protocol):
    def block(self, remote_ip: str, command_id: str) -> str: ...

    def unblock(self, rule_name: str) -> None: ...


class RecoveryRegistry:
    """Persist reversible response metadata so restart does not lose undo/expiry state."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        database_name = str(database_path)
        if database_name != ":memory:":
            Path(database_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_name, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS response_recoveries(
                    command_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1
                )
                """
            )

    def add(self, action: RecoveryAction) -> None:
        with self._connection:
            self._connection.execute(
                """INSERT OR REPLACE INTO response_recoveries
                   (command_id,kind,resource_id,created_at,expires_at,active)
                   VALUES (?,?,?,?,?,?)""",
                (
                    action.command_id,
                    action.kind,
                    action.resource_id,
                    action.created_at.isoformat(),
                    action.expires_at.isoformat() if action.expires_at else None,
                    int(action.active),
                ),
            )

    def list_active(self) -> list[RecoveryAction]:
        rows = self._connection.execute(
            "SELECT * FROM response_recoveries WHERE active=1 ORDER BY created_at DESC"
        ).fetchall()
        return [
            RecoveryAction(
                command_id=row["command_id"], kind=row["kind"], resource_id=row["resource_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                active=bool(row["active"]),
            )
            for row in rows
        ]

    def get(self, command_id: str) -> RecoveryAction:
        row = self._connection.execute(
            "SELECT * FROM response_recoveries WHERE command_id=?", (command_id,)
        ).fetchone()
        if row is None:
            raise KeyError("recovery action was not found")
        return RecoveryAction(
            command_id=row["command_id"], kind=row["kind"], resource_id=row["resource_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            active=bool(row["active"]),
        )

    def deactivate(self, command_id: str) -> None:
        with self._connection:
            self._connection.execute(
                "UPDATE response_recoveries SET active=0 WHERE command_id=?", (command_id,)
            )

    def close(self) -> None:
        self._connection.close()


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
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
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
    _TREE_SCRIPT = """
$root = [int]$env:XDR_PID
$all = Get-CimInstance Win32_Process -ErrorAction Stop
$ids = New-Object System.Collections.Generic.List[int]
$pending = New-Object System.Collections.Generic.Queue[int]
$pending.Enqueue($root)
while ($pending.Count -gt 0) {
    $parent = $pending.Dequeue()
    foreach ($child in $all | Where-Object { $_.ParentProcessId -eq $parent }) {
        $ids.Add([int]$child.ProcessId)
        $pending.Enqueue([int]$child.ProcessId)
    }
}
$ids.Add($root)
@($ids | ForEach-Object {
    $process = Get-Process -Id $_ -ErrorAction Stop
    [pscustomobject]@{ ProcessId=$process.Id; StartTime=$process.StartTime.ToUniversalTime().ToString('o'); ImagePath=$process.Path }
}) | ConvertTo-Json -Compress
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

    def inspect_tree(self, process_id: int) -> list[ProcessIdentity]:
        payload = json.loads(_run_powershell(self._TREE_SCRIPT, {"PID": str(process_id)}))
        rows = payload if isinstance(payload, list) else [payload]
        return [
            ProcessIdentity(process_id=row["ProcessId"], start_time=datetime.fromisoformat(row["StartTime"]), image_path=row["ImagePath"])
            for row in rows
        ]

    def terminate_tree(self, process_ids: list[int]) -> None:
        # inspect_tree가 자식부터 루트 순서로 반환하므로 부모가 자식을 고아로 남기지 않는다.
        for process_id in process_ids:
            self.terminate(process_id)


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

    def block_target(self, command: BlockNetworkCommand) -> str:
        suffix = hashlib.sha256(command.command_id.encode("utf-8")).hexdigest()[:16]
        rule_name = f"WeaveXDR-{suffix}"
        if command.program_path:
            script = """
$name=$env:XDR_RULE_NAME
if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $name -Direction Outbound -Program $env:XDR_PROGRAM -Action Block -ErrorAction Stop | Out-Null
}
$name
"""
            _run_powershell(script, {"RULE_NAME": rule_name, "PROGRAM": command.program_path})
        else:
            _run_powershell(
                self._BLOCK_SCRIPT,
                {"RULE_NAME": rule_name, "REMOTE_IP": command.remote_ip or command.remote_domain or ""},
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
        recovery_registry: RecoveryRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
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
        self.recovery_registry = recovery_registry or RecoveryRegistry()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_attempts = max_attempts

    def preview_impact(self, command: ResponseCommand, incident_report: IncidentReport) -> ImpactPreview:
        preview: DryRunResult = self.dry_run_service.preview(command, incident_report)
        affected: list[str] = []
        protected: list[str] = []
        if isinstance(command, TerminateProcessCommand) and preview.allowed:
            inspector = getattr(self.process_controller, "inspect_tree", None)
            identities = inspector(command.process_id) if inspector else [self.process_controller.inspect(command.process_id)]
            protected_names = {name.lower() for name in self.dry_run_service.policy.protected_process_names}
            for identity in identities:
                label = f"pid={identity.process_id} image={identity.image_path}"
                affected.append(label)
                if PureWindowsPath(identity.image_path).name.lower() in protected_names:
                    protected.append(label)
        elif isinstance(command, BlockNetworkCommand):
            affected.append(preview.target_summary)
        elif isinstance(command, QuarantineFileCommand):
            affected.append(command.file_path)
        return ImpactPreview(
            command_id=command.command_id,
            allowed=preview.allowed and not protected,
            target_summary=preview.target_summary,
            affected_resources=affected,
            protected_resources=protected,
            reversible=preview.reversible,
        )

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
                self._register_recovery(command, resource_id)
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
            impact = self.preview_impact(command, IncidentReport.model_construct(
                incident_id=command.incident_id, recommended_actions=[command.action], source_events=[]
            ))
            if impact.protected_resources:
                raise ValueError("process tree includes a protected system process")
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
            inspector = getattr(self.process_controller, "inspect_tree", None)
            identities = inspector(command.process_id) if inspector else [identity]
            terminator = getattr(self.process_controller, "terminate_tree", None)
            if terminator:
                terminator([item.process_id for item in identities])
            else:
                for item in identities:
                    self.process_controller.terminate(item.process_id)
            return str(command.process_id)
        if isinstance(command, QuarantineFileCommand):
            item = self.quarantine_store.quarantine(
                command.file_path,
                expected_sha256=command.sha256,
                command_id=command.command_id,
            )
            return item.item_id
        if isinstance(command, BlockNetworkCommand):
            blocker = getattr(self.firewall_controller, "block_target", None)
            if blocker:
                return blocker(command)
            if not command.remote_ip:
                raise ValueError("firewall controller only supports IP targets")
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

    def list_recoveries(self) -> list[RecoveryAction]:
        return self.recovery_registry.list_active()

    def undo(self, command_id: str, *, confirmed: bool) -> ExecutionResult:
        if not confirmed:
            raise PermissionError("response undo requires explicit confirmation")
        action = self.recovery_registry.get(command_id)
        if not action.active:
            raise ValueError("response action was already undone")
        if action.kind == "quarantine":
            result = self.restore_quarantine(action.resource_id, confirmed=True)
        else:
            self.remove_network_block(action.resource_id, confirmed=True)
            result = ExecutionResult(command_id=command_id, status="restored", executed=True, attempts=1, resource_id=action.resource_id)
        if result.executed:
            self.recovery_registry.deactivate(command_id)
        return result

    def expire_network_blocks(self, *, now: datetime | None = None) -> list[str]:
        current = (now or self._clock()).astimezone(timezone.utc)
        removed: list[str] = []
        for action in self.recovery_registry.list_active():
            if action.kind == "network_block" and action.expires_at and action.expires_at <= current:
                self.firewall_controller.unblock(action.resource_id)
                self.recovery_registry.deactivate(action.command_id)
                removed.append(action.resource_id)
                self.audit_log.record("recovery", "expire_network_block", "succeeded", action.model_dump(mode="json"))
        return removed

    def close(self) -> None:
        self.recovery_registry.close()

    def _register_recovery(self, command: ResponseCommand, resource_id: str | None) -> None:
        if not resource_id:
            return
        current = self._clock().astimezone(timezone.utc)
        if isinstance(command, QuarantineFileCommand):
            action = RecoveryAction(command_id=command.command_id, kind="quarantine", resource_id=resource_id, created_at=current)
        elif isinstance(command, BlockNetworkCommand):
            action = RecoveryAction(
                command_id=command.command_id, kind="network_block", resource_id=resource_id,
                created_at=current, expires_at=current + timedelta(minutes=command.duration_minutes),
            )
        else:
            return
        self.recovery_registry.add(action)

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
