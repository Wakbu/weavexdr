from xdr_graph.benchmark import compare_benchmark_results


def benchmark(model, *, accuracy, false_positives, false_negatives, p95):
    return {"model": model, "verdict_accuracy": accuracy, "false_positives": false_positives, "false_negatives": false_negatives, "p95_latency_seconds": p95}


def test_model_regression_gate_accepts_equal_or_better_candidate():
    baseline = benchmark("qwen3:4b", accuracy=0.90, false_positives=1, false_negatives=1, p95=10)
    candidate = benchmark("qwen3:8b", accuracy=0.94, false_positives=0, false_negatives=1, p95=12)
    result = compare_benchmark_results(baseline, candidate)
    assert result["passed"] is True
    assert result["accuracy_delta"] == 0.04


def test_model_regression_gate_rejects_accuracy_safety_and_latency_regressions():
    baseline = benchmark("baseline", accuracy=0.95, false_positives=0, false_negatives=0, p95=10)
    candidate = benchmark("candidate", accuracy=0.85, false_positives=1, false_negatives=2, p95=20)
    result = compare_benchmark_results(baseline, candidate)
    assert result["passed"] is False
    assert len(result["failures"]) == 4
