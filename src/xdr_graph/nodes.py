from __future__ import annotations

import ipaddress
from pathlib import PureWindowsPath

from xdr_graph.models import (
    Finding,
    IncidentInput,
    IncidentReport,
    IncidentState,
    ValidationResult,
)
from xdr_graph.model_adapter import ModelAdapter


OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SCRIPT_PROCESSES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "mshta.exe"}
ALLOWED_ACTIONS = {"terminate_process", "quarantine_file", "collect_additional_evidence"}


def normalize_event(state: IncidentState) -> dict:
    incident = IncidentInput.model_validate(state["raw_incident"])
    return {"incident": incident, "review_count": 0}


def analyze_file(state: IncidentState) -> dict:
    findings: list[Finding] = []
    for event in state["incident"].events:
        if event.event_type != "file_create" or not event.file_path:
            continue

        path = PureWindowsPath(event.file_path)
        lowered = str(path).lower()
        if path.suffix.lower() in {".exe", ".dll", ".scr", ".ps1"} and any(
            marker in lowered for marker in ("\\temp\\", "\\appdata\\", "\\downloads\\")
        ):
            findings.append(
                Finding(
                    source="file",
                    rule_id="FILE-001",
                    severity=30,
                    reason="Executable or script created in a user-writable directory",
                    event_ids=[event.event_id],
                )
            )
    return {"findings": findings}


def analyze_behavior(state: IncidentState) -> dict:
    findings: list[Finding] = []
    for event in state["incident"].events:
        if event.event_type != "process_start":
            continue

        process = (event.process_name or "").lower()
        parent = (event.parent_process or "").lower()
        command = (event.command_line or "").lower()

        if parent in OFFICE_PROCESSES and process in SCRIPT_PROCESSES:
            findings.append(
                Finding(
                    source="behavior",
                    rule_id="PROC-001",
                    severity=40,
                    reason="Office application spawned a script interpreter",
                    event_ids=[event.event_id],
                )
            )
        if process in {"powershell.exe", "pwsh.exe"} and any(
            marker in command for marker in (" -enc ", " -encodedcommand ", "frombase64string")
        ):
            findings.append(
                Finding(
                    source="behavior",
                    rule_id="PROC-002",
                    severity=35,
                    reason="PowerShell used an encoded or Base64-oriented command",
                    event_ids=[event.event_id],
                )
            )
    return {"findings": findings}


def analyze_network(state: IncidentState) -> dict:
    findings: list[Finding] = []
    for event in state["incident"].events:
        if event.event_type != "network_connect" or not event.destination_ip:
            continue
        try:
            destination = ipaddress.ip_address(event.destination_ip)
        except ValueError:
            continue

        process = (event.process_name or "").lower()
        if destination.is_global and process in SCRIPT_PROCESSES:
            findings.append(
                Finding(
                    source="network",
                    rule_id="NET-001",
                    severity=20,
                    reason="Script interpreter connected to a public IP address",
                    event_ids=[event.event_id],
                )
            )
    return {"findings": findings}


def synthesize_incident(state: IncidentState, model_adapter: ModelAdapter) -> dict:
    decision = model_adapter.synthesize(state["incident"], state.get("findings", []))
    return decision.model_dump()


def verify_incident(state: IncidentState) -> dict:
    errors: list[str] = []
    findings = state.get("findings", [])

    if state["verdict"] == "suspicious":
        sources = {finding.source for finding in findings}
        if len(sources) < 2:
            errors.append("Suspicious verdict requires corroboration from at least two analysis sources")

    if any(not finding.event_ids for finding in findings):
        errors.append("Every finding must reference at least one source event")

    # 모델이 생성한 설명은 원본 분석 노드의 Finding에 존재하는 내용만 허용한다.
    # 이 검사는 프롬프트 인젝션이나 모델 환각이 사건 근거로 승격되는 것을 막는다.
    finding_reasons = {finding.reason for finding in findings}
    unsupported_evidence = set(state.get("evidence", [])) - finding_reasons
    if unsupported_evidence:
        errors.append("Synthesis evidence must be grounded in analyzer findings")

    # 실제 대응 서비스가 구현되더라도 모델이 임의 명령이나 예상하지 못한
    # 조치를 추가하지 못하도록 그래프 단계에서 먼저 허용 목록을 적용한다.
    proposed_actions = set(state.get("proposed_actions", []))
    if proposed_actions - ALLOWED_ACTIONS:
        errors.append("Synthesis proposed an action outside the response allowlist")
    if state["verdict"] == "benign" and proposed_actions:
        errors.append("Benign verdict cannot propose response actions")

    return {
        "validation_errors": errors,
        "review_count": state.get("review_count", 0) + 1,
    }


def route_after_verification(state: IncidentState) -> str:
    if state.get("validation_errors") and state.get("review_count", 0) < 2:
        return "revise"
    return "accepted"


def reassess_incident(state: IncidentState) -> dict:
    return {
        "verdict": "needs_review",
        "proposed_actions": ["collect_additional_evidence"],
    }


def create_report(state: IncidentState) -> dict:
    validation_errors = state.get("validation_errors", [])
    verdict = "needs_review" if validation_errors else state["verdict"]
    actions = ["collect_additional_evidence"] if validation_errors else state["proposed_actions"]
    report = IncidentReport(
        incident_id=state["incident"].incident_id,
        verdict=verdict,
        risk_score=state["risk_score"],
        evidence=state.get("evidence", []),
        recommended_actions=actions,
        validation=ValidationResult(
            passed=not validation_errors,
            errors=validation_errors,
            review_count=state.get("review_count", 0),
        ),
    )
    return {"report": report}
