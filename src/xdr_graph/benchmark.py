from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from xdr_graph.evaluation import load_cases
from xdr_graph.model_adapter import (
    FallbackModelAdapter,
    OllamaModelAdapter,
    PolicyGuardedModelAdapter,
)
from xdr_graph.workflow import build_workflow


def compare_benchmark_results(baseline: dict, candidate: dict, *, max_accuracy_drop: float = 0.02, max_p95_ratio: float = 1.5) -> dict:
    """Gate a candidate model with explicit accuracy, FP/FN and latency regressions."""
    failures: list[str] = []
    accuracy_delta = round(float(candidate["verdict_accuracy"]) - float(baseline["verdict_accuracy"]), 4)
    p95_ratio = round(float(candidate["p95_latency_seconds"]) / max(float(baseline["p95_latency_seconds"]), 0.001), 4)
    false_positive_delta = int(candidate["false_positives"]) - int(baseline["false_positives"])
    false_negative_delta = int(candidate["false_negatives"]) - int(baseline["false_negatives"])
    if accuracy_delta < -max_accuracy_drop:
        failures.append(f"accuracy dropped by {abs(accuracy_delta):.4f}")
    if false_positive_delta > 0:
        failures.append(f"false positives increased by {false_positive_delta}")
    if false_negative_delta > 0:
        failures.append(f"false negatives increased by {false_negative_delta}")
    if p95_ratio > max_p95_ratio:
        failures.append(f"p95 latency ratio {p95_ratio:.2f} exceeded {max_p95_ratio:.2f}")
    return {"baseline_model": baseline.get("model"), "candidate_model": candidate.get("model"), "passed": not failures, "failures": failures, "accuracy_delta": accuracy_delta, "false_positive_delta": false_positive_delta, "false_negative_delta": false_negative_delta, "p95_latency_ratio": p95_ratio}


def run_benchmark(dataset: Path, model: str, timeout_seconds: float) -> dict:
    local_model = OllamaModelAdapter(model=model, timeout_seconds=timeout_seconds)
    safe_model = PolicyGuardedModelAdapter(local_model)
    model_with_fallback = FallbackModelAdapter(safe_model)
    workflow = build_workflow(model_with_fallback)
    latencies: list[float] = []
    verdict_matches = 0
    false_positives = 0
    false_negatives = 0
    cases = load_cases(dataset)

    # 첫 호출에는 모델을 GPU에 적재하는 시간이 포함된다. 실제 사건 처리
    # 지연 시간과 구분하기 위해 준비 호출을 별도로 측정하고 본 평가에서 제외한다.
    warmup_started = time.perf_counter()
    workflow.invoke(
        {"raw_incident": cases[0].incident.model_dump(mode="json"), "findings": []}
    )
    warmup_seconds = time.perf_counter() - warmup_started

    for case in cases:
        started = time.perf_counter()
        result = workflow.invoke(
            {"raw_incident": case.incident.model_dump(mode="json"), "findings": []}
        )
        latencies.append(time.perf_counter() - started)
        actual = result["report"].verdict
        verdict_matches += actual == case.expected.verdict
        false_positives += case.expected.verdict == "benign" and actual != "benign"
        false_negatives += case.expected.verdict == "suspicious" and actual != "suspicious"

    ordered = sorted(latencies)
    p95_index = min(int(len(ordered) * 0.95), len(ordered) - 1)
    return {
        "model": model,
        "total_cases": len(latencies),
        "verdict_matches": verdict_matches,
        "verdict_accuracy": round(verdict_matches / len(latencies), 4),
        "fallback_count": model_with_fallback.fallback_count,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "warmup_seconds": round(warmup_seconds, 3),
        "average_latency_seconds": round(statistics.mean(latencies), 3),
        "p95_latency_seconds": round(ordered[p95_index], 3),
        "max_latency_seconds": round(max(latencies), 3),
        "last_error": model_with_fallback.last_error,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark a local XDR synthesis model")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--model", default="qwen3:8b")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--baseline", type=Path, help="Compare the candidate result with a previous benchmark JSON")
    parser.add_argument("--output", type=Path, help="Write the benchmark JSON for later regression comparisons")
    args = parser.parse_args()
    result = run_benchmark(args.dataset, args.model, args.timeout)
    output = {"benchmark": result}
    if args.baseline:
        baseline_payload = json.loads(args.baseline.read_text(encoding="utf-8"))
        output["regression"] = compare_benchmark_results(baseline_payload.get("benchmark", baseline_payload), result)
    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
