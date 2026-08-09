import hashlib
import json
from pathlib import Path

import pytest

from xdr_graph.detection import (
    DEFAULT_RULES_PATH,
    DetectionRuleEngine,
    RuleBundleManager,
)
from xdr_graph.models import IncidentInput
from xdr_graph.risk_policy import load_default_risk_policy


PROJECT_ROOT = Path(__file__).parents[1]
SAMPLE_BATCH = PROJECT_ROOT / "samples" / "suspicious_office_batch.json"


def load_sample_incident() -> IncidentInput:
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    return IncidentInput(
        incident_id=raw_batch["incident_id"], events=raw_batch["events"]
    )


def test_external_rule_bundle_reproduces_existing_detections_with_references():
    bundle = RuleBundleManager.validate_file(DEFAULT_RULES_PATH)
    engine = DetectionRuleEngine(bundle)
    incident = load_sample_incident()

    findings = [
        *engine.analyze(incident.events, "file"),
        *engine.analyze(incident.events, "behavior"),
        *engine.analyze(incident.events, "network"),
    ]

    assert {finding.rule_id for finding in findings} == {
        "FILE-001",
        "PROC-001",
        "PROC-002",
        "NET-001",
    }
    assert all(finding.references for finding in findings)
    assert {source.framework for source in bundle.sources} == {
        "owasp",
        "owasp_genai",
        "mitre_attack",
        "cisa_kev",
    }


def test_rule_bundle_requires_matching_checksum_and_supports_rollback():
    expected_hash = hashlib.sha256(DEFAULT_RULES_PATH.read_bytes()).hexdigest()
    original = RuleBundleManager.validate_file(
        DEFAULT_RULES_PATH, expected_sha256=expected_hash
    )
    manager = RuleBundleManager(original)
    candidate = original.model_copy(update={"rule_version": "candidate-version"})

    manager.activate(candidate)
    assert manager.active_bundle.rule_version == "candidate-version"
    manager.rollback()
    assert manager.active_bundle.rule_version == original.rule_version

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        RuleBundleManager.validate_file(DEFAULT_RULES_PATH, expected_sha256="0" * 64)


def test_risk_policy_uses_configured_thresholds():
    policy = load_default_risk_policy()
    bundle = RuleBundleManager.validate_file(DEFAULT_RULES_PATH)
    findings = DetectionRuleEngine(bundle).analyze(
        load_sample_incident().events, "behavior"
    )

    decision = policy.decide(findings)

    assert decision.score == 75
    assert decision.verdict == "suspicious"
    assert decision.actions == ["terminate_process", "quarantine_file", "block_network"]
