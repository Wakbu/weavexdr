from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from xdr_graph.models import Finding


_packaged_config = Path(__file__).parent / "config"
_source_config = Path(__file__).parents[2] / "config"
DEFAULT_POLICY_PATH = (_packaged_config if _packaged_config.is_dir() else _source_config) / "risk-policy.json"


class RiskDecision(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Literal["benign", "needs_review", "suspicious"]
    actions: list[str]


class RiskPolicy(BaseModel):
    """모델과 독립적으로 적용되는 점수·판정·대응 임계값."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    policy_version: str = Field(min_length=1)
    maximum_score: int = Field(default=100, ge=1, le=100)
    needs_review_min_score: int = Field(ge=1, le=100)
    suspicious_min_score: int = Field(ge=1, le=100)
    suspicious_actions: list[str]
    review_actions: list[str]

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "RiskPolicy":
        if self.needs_review_min_score >= self.suspicious_min_score:
            raise ValueError("review threshold must be below suspicious threshold")
        return self

    def decide(self, findings: Sequence[Finding]) -> RiskDecision:
        score = min(sum(finding.severity for finding in findings), self.maximum_score)
        if score >= self.suspicious_min_score:
            return RiskDecision(
                score=score, verdict="suspicious", actions=self.suspicious_actions
            )
        if score >= self.needs_review_min_score:
            return RiskDecision(
                score=score, verdict="needs_review", actions=self.review_actions
            )
        return RiskDecision(score=score, verdict="benign", actions=[])


@lru_cache(maxsize=1)
def load_default_risk_policy() -> RiskPolicy:
    return RiskPolicy.model_validate_json(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
