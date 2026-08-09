from __future__ import annotations

import argparse
import json
from pathlib import Path

from xdr_graph.model_adapter import (
    FallbackModelAdapter,
    OllamaModelAdapter,
    PolicyGuardedModelAdapter,
)
from xdr_graph.workflow import build_workflow


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the personal XDR graph skeleton")
    parser.add_argument("incident", type=Path, help="Path to an incident JSON file")
    parser.add_argument(
        "--provider",
        choices=("rule", "ollama"),
        default="rule",
        help="Synthesis provider. Rule mode remains the safe default.",
    )
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model name")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    raw_incident = json.loads(args.incident.read_text(encoding="utf-8"))

    model_adapter = None
    if args.provider == "ollama":
        # 로컬 모델 출력은 정책 가드로 제한하고, 서버 중단이나 스키마 오류가
        # 발생하면 결정론적 규칙 모델로 자동 복귀해 사건 처리를 계속한다.
        local_model = OllamaModelAdapter(model=args.model, timeout_seconds=args.timeout)
        guarded_model = PolicyGuardedModelAdapter(local_model)
        model_adapter = FallbackModelAdapter(guarded_model)

    workflow = build_workflow(model_adapter)
    result = workflow.invoke({"raw_incident": raw_incident, "findings": []})
    print(result["report"].model_dump_json(indent=2))


if __name__ == "__main__":
    main()
