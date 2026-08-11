from __future__ import annotations

from xdr_graph.correlation import EventCorrelationEngine
from xdr_graph.detection import DetectionRuleEngine, load_default_detection_engine
from xdr_graph.allowlist import AllowlistEngine, load_default_allowlist_engine
from xdr_graph.response import load_default_response_policy
from xdr_graph.models import (
    Finding,
    IncidentInput,
    IncidentReport,
    IncidentState,
    ValidationResult,
)
from xdr_graph.model_adapter import ModelAdapter


def normalize_event(state: IncidentState) -> dict:
    incident = IncidentInput.model_validate(state["raw_incident"])
    return {"incident": incident, "review_count": 0}


def analyze_file(
    state: IncidentState, engine: DetectionRuleEngine | None = None
) -> dict:
    active_engine = engine or load_default_detection_engine()
    return {"findings": active_engine.analyze(state["incident"].events, "file")}


def analyze_behavior(
    state: IncidentState, engine: DetectionRuleEngine | None = None
) -> dict:
    active_engine = engine or load_default_detection_engine()
    return {"findings": active_engine.analyze(state["incident"].events, "behavior")}


def analyze_network(
    state: IncidentState, engine: DetectionRuleEngine | None = None
) -> dict:
    active_engine = engine or load_default_detection_engine()
    return {"findings": active_engine.analyze(state["incident"].events, "network")}


def correlate_events(
    state: IncidentState, engine: EventCorrelationEngine | None = None
) -> dict:
    active_engine = engine or EventCorrelationEngine()
    chains, findings = active_engine.correlate(state["incident"].events)
    return {"attack_chains": chains, "findings": findings}


def apply_allowlist(
    state: IncidentState, engine: AllowlistEngine | None = None
) -> dict:
    active_engine = engine or load_default_allowlist_engine()
    remaining, suppressed = active_engine.apply(
        state.get("findings", []), state["incident"].events
    )
    return {"effective_findings": remaining, "suppressed_findings": suppressed}


def synthesize_incident(state: IncidentState, model_adapter: ModelAdapter) -> dict:
    findings = state.get("effective_findings", state.get("findings", []))
    comparison_method = getattr(model_adapter, "synthesize_with_comparison", None)
    if comparison_method:
        decision, comparison = comparison_method(state["incident"], findings)
        output = decision.model_dump(); output["model_comparison"] = comparison
        output["uncertainty_score"] = comparison.uncertainty_score
        output["additional_evidence_requested"] = comparison.uncertainty_score >= 20
        return output
    decision = model_adapter.synthesize(state["incident"], findings)
    return {**decision.model_dump(), "uncertainty_score": 0, "additional_evidence_requested": False}


def verify_incident(state: IncidentState) -> dict:
    errors: list[str] = []
    findings = state.get("effective_findings", state.get("findings", []))

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
    allowed_actions = set(load_default_response_policy().allowed_actions)
    if proposed_actions - allowed_actions:
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
    actions = ["collect_additional_evidence"] if validation_errors else list(state["proposed_actions"])
    if state.get("additional_evidence_requested") and "collect_additional_evidence" not in actions:
        actions.append("collect_additional_evidence")
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
        findings=state.get("effective_findings", state.get("findings", [])),
        suppressed_findings=state.get("suppressed_findings", []),
        attack_chains=state.get("attack_chains", []),
        source_events=state["incident"].events,
        agent_traces=state.get("agent_traces", []),
        model_comparison=state.get("model_comparison"),
        uncertainty_score=state.get("uncertainty_score", 0),
        additional_evidence_requested=state.get("additional_evidence_requested", False),
    )
    return {"report": report}
