import json
from pathlib import Path

import pytest

from xdr_graph.evaluation import evaluate_case, load_cases
from xdr_graph.model_adapter import (
    ComparingModelAdapter,
    FallbackModelAdapter,
    ModelAdapterError,
    OllamaModelAdapter,
    PolicyGuardedModelAdapter,
    RuleBasedModelAdapter,
    SynthesisDecision,
)
from xdr_graph.workflow import build_workflow


DATASET = Path(__file__).parents[1] / "evaluations" / "incidents.json"


def run_incident(events: list[dict]):
    result = build_workflow().invoke(
        {
            "raw_incident": {"incident_id": "test-incident", "events": events},
            "findings": [],
        }
    )
    return result["report"]


def test_corroborated_incident_is_suspicious():
    report = run_incident(
        [
            {
                "event_id": "p1",
                "event_type": "process_start",
                "timestamp": "2026-08-06T10:00:00+09:00",
                "process_name": "powershell.exe",
                "parent_process": "WINWORD.EXE",
                "command_line": "powershell.exe -enc SQBFAFgA",
            },
            {
                "event_id": "f1",
                "event_type": "file_create",
                "timestamp": "2026-08-06T10:00:01+09:00",
                "process_name": "powershell.exe",
                "file_path": "C:\\Users\\user\\AppData\\Local\\Temp\\dropper.exe",
            },
        ]
    )

    assert report.verdict == "suspicious"
    assert report.risk_score == 100
    assert report.validation.passed is True
    assert report.validation.review_count == 1
    assert "quarantine_file" in report.recommended_actions


def test_single_source_suspicion_is_downgraded_for_review():
    report = run_incident(
        [
            {
                "event_id": "p1",
                "event_type": "process_start",
                "timestamp": "2026-08-06T10:00:00+09:00",
                "process_name": "powershell.exe",
                "parent_process": "WINWORD.EXE",
                "command_line": "powershell.exe -enc SQBFAFgA",
            }
        ]
    )

    assert report.risk_score == 75
    assert report.verdict == "needs_review"
    assert report.validation.passed is True
    assert report.validation.review_count == 2
    assert report.validation.errors == []
    assert report.recommended_actions == ["collect_additional_evidence"]


def test_normal_process_is_benign():
    report = run_incident(
        [
            {
                "event_id": "p1",
                "event_type": "process_start",
                "timestamp": "2026-08-06T10:00:00+09:00",
                "process_name": "notepad.exe",
                "parent_process": "explorer.exe",
                "command_line": "notepad.exe notes.txt",
            }
        ]
    )

    assert report.verdict == "benign"
    assert report.risk_score == 0
    assert report.validation.passed is True
    assert report.recommended_actions == []


@pytest.mark.parametrize("case", load_cases(DATASET), ids=lambda case: case.case_id)
def test_evaluation_dataset(case):
    result = evaluate_case(case)
    assert result.passed, result.failures


def test_custom_model_adapter_can_replace_baseline():
    class StubAdapter:
        def synthesize(self, incident, findings):
            return SynthesisDecision(
                risk_score=42,
                verdict="needs_review",
                evidence=[f"adapter handled {incident.incident_id}"],
                proposed_actions=["collect_additional_evidence"],
            )

    result = build_workflow(StubAdapter()).invoke(
        {
            "raw_incident": {
                "incident_id": "adapter-test",
                "events": [
                    {
                        "event_id": "p1",
                        "event_type": "process_start",
                        "timestamp": "2026-08-08T10:00:00+09:00",
                        "process_name": "notepad.exe",
                    }
                ],
            },
            "findings": [],
        }
    )

    assert result["report"].risk_score == 42
    assert result["report"].evidence == ["adapter handled adapter-test"]


def test_ollama_adapter_validates_structured_output():
    content = SynthesisDecision(
        risk_score=0,
        verdict="benign",
        evidence=[],
        proposed_actions=[],
    ).model_dump_json()

    def transport(request, timeout):
        assert timeout == 5
        assert request.full_url.endswith("/api/chat")
        return json.dumps(
            {
                "message": {"content": content},
                "total_duration": 1_000_000_000,
                "prompt_eval_count": 10,
                "eval_count": 5,
                "eval_duration": 500_000_000,
            }
        ).encode()

    adapter = OllamaModelAdapter(timeout_seconds=5, transport=transport)
    incident = load_cases(DATASET)[0].incident
    decision = adapter.synthesize(incident, [])

    assert decision.verdict == "benign"
    assert adapter.last_metrics is not None
    assert adapter.last_metrics.output_tokens_per_second == 10


def test_failed_local_model_uses_rule_fallback():
    class FailedAdapter:
        def synthesize(self, incident, findings):
            raise ModelAdapterError("timeout")

    adapter = FallbackModelAdapter(FailedAdapter(), RuleBasedModelAdapter())
    incident = load_cases(DATASET)[0].incident
    decision = adapter.synthesize(incident, [])

    assert decision.verdict == "benign"
    assert adapter.fallback_count == 1
    assert adapter.last_error == "timeout"


def test_policy_guard_corrects_unsupported_model_verdict():
    class IncorrectAdapter:
        def synthesize(self, incident, findings):
            return SynthesisDecision(
                risk_score=30,
                verdict="needs_review",
                evidence=["unsupported evidence"],
                proposed_actions=["collect_additional_evidence"],
            )

    case = load_cases(DATASET)[5]
    result = build_workflow(PolicyGuardedModelAdapter(IncorrectAdapter())).invoke(
        {"raw_incident": case.incident.model_dump(mode="json"), "findings": []}
    )

    assert result["report"].verdict == "benign"
    assert result["report"].risk_score == 30
    assert result["report"].evidence == [
        "Executable or script created in a user-writable directory"
    ]


def test_workflow_records_each_agent_trace_without_raw_event_payloads():
    case = load_cases(DATASET)[0]
    report = build_workflow().invoke({"raw_incident": case.incident.model_dump(mode="json"), "findings": []})["report"]
    nodes = {trace.node for trace in report.agent_traces}
    assert {"normalize", "file_analysis", "behavior_analysis", "network_analysis", "correlate", "allowlist", "synthesize", "verify", "report"} <= nodes
    assert all(trace.duration_ms >= 0 and trace.input_count >= 0 for trace in report.agent_traces)


def test_model_comparison_keeps_rule_decision_and_requests_evidence_on_disagreement():
    case = load_cases(DATASET)[5]
    model = SynthesisDecision(risk_score=100, verdict="suspicious", evidence=[], proposed_actions=[])
    def transport(request, timeout):
        return json.dumps({"message": {"content": model.model_dump_json()}}).encode()
    adapter = ComparingModelAdapter(lambda: OllamaModelAdapter(model="qwen3:4b", transport=transport), lambda: "qwen3:4b")
    report = build_workflow(adapter).invoke({"raw_incident": case.incident.model_dump(mode="json"), "findings": []})["report"]
    assert report.risk_score == 30 and report.verdict == "benign"
    assert report.model_comparison is not None and report.model_comparison.agreed is False
    assert report.additional_evidence_requested is True
    assert "collect_additional_evidence" in report.recommended_actions


def test_ollama_adapter_rejects_non_loopback_and_extra_output_fields():
    with pytest.raises(ValueError, match="loopback"):
        OllamaModelAdapter(endpoint="https://models.example/api/chat")
    def transport(request, timeout):
        return json.dumps({"message": {"content": '{"risk_score":0,"verdict":"benign","evidence":[],"proposed_actions":[],"tool_call":"powershell"}'}}).encode()
    with pytest.raises(ModelAdapterError):
        OllamaModelAdapter(transport=transport).synthesize(load_cases(DATASET)[0].incident, [])
