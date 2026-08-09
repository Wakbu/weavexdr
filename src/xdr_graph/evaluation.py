from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from xdr_graph.models import IncidentInput
from xdr_graph.workflow import build_workflow


class ExpectedOutcome(BaseModel):
    verdict: Literal["benign", "needs_review", "suspicious"]
    min_score: int = Field(ge=0, le=100)
    max_score: int = Field(ge=0, le=100)
    required_rule_ids: list[str] = Field(default_factory=list)


class EvaluationCase(BaseModel):
    case_id: str
    description: str
    incident: IncidentInput
    expected: ExpectedOutcome


class CaseResult(BaseModel):
    case_id: str
    passed: bool
    failures: list[str]


def load_cases(path: Path) -> list[EvaluationCase]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [EvaluationCase.model_validate(item) for item in data]


def evaluate_case(case: EvaluationCase) -> CaseResult:
    # 평가는 실제 그래프 전체를 실행한다. 개별 규칙 함수만 검사하지 않아
    # 병렬 분석, 종합, 재검증 과정에서 생기는 회귀까지 함께 탐지한다.
    result = build_workflow().invoke(
        {"raw_incident": case.incident.model_dump(mode="json"), "findings": []}
    )
    report = result["report"]
    rule_ids = {finding.rule_id for finding in result.get("findings", [])}
    failures: list[str] = []

    # 판정뿐 아니라 점수 범위와 필수 규칙까지 확인해 우연히 같은 판정이
    # 나온 경우를 통과시키지 않는다.
    if report.verdict != case.expected.verdict:
        failures.append(f"verdict: expected {case.expected.verdict}, got {report.verdict}")
    if not case.expected.min_score <= report.risk_score <= case.expected.max_score:
        failures.append(
            f"risk_score: expected {case.expected.min_score}-{case.expected.max_score}, "
            f"got {report.risk_score}"
        )
    missing_rules = set(case.expected.required_rule_ids) - rule_ids
    if missing_rules:
        failures.append(f"missing rules: {sorted(missing_rules)}")

    return CaseResult(case_id=case.case_id, passed=not failures, failures=failures)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the XDR graph baseline")
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()

    results = [evaluate_case(case) for case in load_cases(args.dataset)]
    output = {
        "passed": sum(result.passed for result in results),
        "total": len(results),
        "results": [result.model_dump() for result in results],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    raise SystemExit(0 if output["passed"] == output["total"] else 1)


if __name__ == "__main__":
    main()
