import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from xdr_graph.audit import SQLiteAuditLog
from xdr_graph.ingestion import GraphIngestionService
from xdr_graph.quarantine import QuarantineItem
from xdr_graph.response import (
    ApprovalService,
    BlockNetworkCommand,
    DryRunResponseService,
    QuarantineFileCommand,
    TerminateProcessCommand,
)
from xdr_graph.response_execution import ActualResponseService, ProcessIdentity
from xdr_graph.workflow import build_workflow


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"
NOW = datetime(2026, 8, 9, 1, 0, tzinfo=timezone.utc)


def suspicious_report():
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    return build_workflow().invoke(
        {
            "raw_incident": {
                "incident_id": raw_batch["incident_id"],
                "events": raw_batch["events"],
            },
            "findings": [],
        }
    )["report"]


class FakeProcessController:
    def __init__(self, *, fail_once: bool = False, changed: bool = False) -> None:
        self.fail_once = fail_once
        self.changed = changed
        self.terminated: list[int] = []

    def inspect(self, process_id: int) -> ProcessIdentity:
        return ProcessIdentity(
            process_id=process_id,
            start_time=NOW + (timedelta(seconds=5) if self.changed else timedelta()),
            image_path="C:\\Tools\\powershell.exe",
        )

    def terminate(self, process_id: int) -> None:
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("temporary process error")
        self.terminated.append(process_id)


class FakeQuarantineStore:
    def quarantine(self, file_path, *, expected_sha256, command_id):
        return QuarantineItem(
            item_id="quarantine-item",
            command_id=command_id,
            original_path=str(file_path),
            quarantine_path="C:\\Quarantine\\item.bin",
            sha256=expected_sha256,
            status="quarantined",
            quarantined_at=NOW,
        )

    def restore(self, item_id):
        return QuarantineItem(
            item_id=item_id,
            command_id="quarantine-command",
            original_path="C:\\Temp\\payload.exe",
            quarantine_path="C:\\Quarantine\\item.bin",
            sha256="a" * 64,
            status="restored",
            quarantined_at=NOW,
            restored_at=NOW,
        )


class FakeFirewallController:
    def __init__(self) -> None:
        self.blocked: list[str] = []
        self.unblocked: list[str] = []

    def block(self, remote_ip: str, command_id: str) -> str:
        self.blocked.append(remote_ip)
        return "WeaveXDR-test-rule"

    def unblock(self, rule_name: str) -> None:
        self.unblocked.append(rule_name)


def approved_execution_service(process_controller=None):
    audit = SQLiteAuditLog(":memory:", clock=lambda: NOW)
    approval = ApprovalService(clock=lambda: NOW)
    firewall = FakeFirewallController()
    service = ActualResponseService(
        DryRunResponseService(),
        approval,
        audit,
        FakeQuarantineStore(),
        process_controller=process_controller or FakeProcessController(),
        firewall_controller=firewall,
    )
    return service, approval, audit, firewall


def terminate_command(command_id="terminate-command"):
    return TerminateProcessCommand(
        command_id=command_id,
        incident_id="incident-001",
        action="terminate_process",
        requested_at=NOW,
        process_id=4242,
        process_start_time=NOW,
        process_image_path="C:\\Tools\\powershell.exe",
    )


def approve(command, report, service, approval_service):
    preview = service.dry_run_service.preview(command, report)
    record = approval_service.request(preview)
    approval_service.decide(record.approval_id, approve=True, approver="local-user")
    return record.approval_id


def test_process_is_revalidated_retried_and_audited_before_termination():
    controller = FakeProcessController(fail_once=True)
    service, approval, audit, _ = approved_execution_service(controller)
    report = suspicious_report()
    command = terminate_command()
    approval_id = approve(command, report, service, approval)

    result = service.execute(command, report, approval_id=approval_id)

    assert result.status == "succeeded"
    assert result.attempts == 2
    assert controller.terminated == [4242]
    assert audit.verify_integrity() is True
    assert [record.status for record in audit.list_records()] == [
        "started",
        "attempt_failed",
        "succeeded",
    ]


def test_changed_process_identity_is_never_terminated_and_requires_review():
    controller = FakeProcessController(changed=True)
    service, approval, audit, _ = approved_execution_service(controller)
    report = suspicious_report()
    command = terminate_command("changed-process")
    approval_id = approve(command, report, service, approval)

    result = service.execute(command, report, approval_id=approval_id)

    assert result.status == "failed"
    assert result.recovery_status == "manual_review_required"
    assert controller.terminated == []
    assert audit.list_records()[-1].category == "recovery"


def test_network_block_and_explicit_unblock_use_reversible_rule_id():
    service, approval, audit, firewall = approved_execution_service()
    report = suspicious_report()
    command = BlockNetworkCommand(
        command_id="network-command",
        incident_id="incident-001",
        action="block_network",
        requested_at=NOW,
        remote_ip="8.8.8.8",
    )
    approval_id = approve(command, report, service, approval)

    result = service.execute(command, report, approval_id=approval_id)
    service.remove_network_block(result.resource_id, confirmed=True)

    assert result.resource_id == "WeaveXDR-test-rule"
    assert firewall.blocked == ["8.8.8.8"]
    assert firewall.unblocked == ["WeaveXDR-test-rule"]
    assert audit.verify_integrity() is True


def test_file_quarantine_and_restore_keep_recovery_metadata():
    service, approval, audit, _ = approved_execution_service()
    report = suspicious_report()
    command = QuarantineFileCommand(
        command_id="quarantine-command",
        incident_id="incident-001",
        action="quarantine_file",
        requested_at=NOW,
        file_path="C:\\Temp\\payload.exe",
        sha256="a" * 64,
    )
    approval_id = approve(command, report, service, approval)

    result = service.execute(command, report, approval_id=approval_id)
    restored = service.restore_quarantine(result.resource_id, confirmed=True)

    assert result.status == "succeeded"
    assert result.resource_id == "quarantine-item"
    assert restored.status == "restored"
    assert audit.list_records()[-1].action == "restore_quarantine"


def test_analysis_summary_is_written_to_the_same_audit_contract():
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    with SQLiteAuditLog(":memory:", clock=lambda: NOW) as audit:
        receipt = GraphIngestionService(audit_logger=audit).submit_raw(raw_batch)

        record = audit.list_records()[0]
        assert record.category == "analysis"
        assert record.details["incident_id"] == receipt.incident_id
        assert record.details["risk_score"] == receipt.report.risk_score
