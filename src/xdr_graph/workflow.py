from time import perf_counter

from langgraph.graph import END, START, StateGraph

from xdr_graph.model_adapter import ModelAdapter, RuleBasedModelAdapter
from xdr_graph.correlation import EventCorrelationEngine
from xdr_graph.detection import DetectionRuleEngine, load_default_detection_engine
from xdr_graph.allowlist import AllowlistEngine, load_default_allowlist_engine
from xdr_graph.models import AgentTrace, IncidentState
from xdr_graph.nodes import (
    analyze_behavior,
    analyze_file,
    analyze_network,
    apply_allowlist,
    create_report,
    correlate_events,
    normalize_event,
    reassess_incident,
    route_after_verification,
    synthesize_incident,
    verify_incident,
)


def build_workflow(
    model_adapter: ModelAdapter | None = None,
    detection_engine: DetectionRuleEngine | None = None,
    correlation_engine: EventCorrelationEngine | None = None,
    allowlist_engine: AllowlistEngine | None = None,
):
    adapter = model_adapter or RuleBasedModelAdapter()
    rules = detection_engine or load_default_detection_engine()
    correlator = correlation_engine or EventCorrelationEngine()
    allowlist = allowlist_engine or load_default_allowlist_engine()
    graph = StateGraph(IncidentState)

    def traced(node_name, worker):
        def invoke(state):
            started = perf_counter(); output = worker(state)
            findings = output.get("findings", []) if isinstance(output, dict) else []
            evidence_ids = list(dict.fromkeys(event_id for finding in findings for event_id in getattr(finding, "event_ids", [])))[:100]
            input_count = len(state.get("incident", {}).events) if hasattr(state.get("incident"), "events") else len(state.get("raw_incident", {}).get("events", []))
            output_count = len(findings) or len(output) if isinstance(output, dict) else 0
            fallback = bool(getattr(output.get("model_comparison"), "fallback_used", False)) if isinstance(output, dict) else False
            trace = AgentTrace(node=node_name, duration_ms=round((perf_counter()-started)*1000, 3), input_count=input_count, output_count=output_count, evidence_event_ids=evidence_ids, status="fallback" if fallback else "succeeded")
            if isinstance(output, dict) and output.get("report"):
                report = output["report"]
                output = {**output, "report": report.model_copy(update={"agent_traces": [*report.agent_traces, trace]})}
            return {**output, "agent_traces": [trace]}
        return invoke

    graph.add_node("normalize", traced("normalize", normalize_event))
    graph.add_node("file_analysis", traced("file_analysis", lambda state: analyze_file(state, rules)))
    graph.add_node("behavior_analysis", traced("behavior_analysis", lambda state: analyze_behavior(state, rules)))
    graph.add_node("network_analysis", traced("network_analysis", lambda state: analyze_network(state, rules)))
    graph.add_node("correlate", traced("correlate", lambda state: correlate_events(state, correlator)))
    graph.add_node("allowlist", traced("allowlist", lambda state: apply_allowlist(state, allowlist)))
    graph.add_node("synthesize", traced("synthesize", lambda state: synthesize_incident(state, adapter)))
    graph.add_node("verify", traced("verify", verify_incident))
    graph.add_node("reassess", traced("reassess", reassess_incident))
    graph.add_node("report", traced("report", create_report))

    graph.add_edge(START, "normalize")
    graph.add_edge("normalize", "file_analysis")
    graph.add_edge("normalize", "behavior_analysis")
    graph.add_edge("normalize", "network_analysis")
    graph.add_edge("file_analysis", "correlate")
    graph.add_edge("behavior_analysis", "correlate")
    graph.add_edge("network_analysis", "correlate")
    graph.add_edge("correlate", "allowlist")
    graph.add_edge("allowlist", "synthesize")
    graph.add_edge("synthesize", "verify")
    graph.add_conditional_edges(
        "verify",
        route_after_verification,
        {"revise": "reassess", "accepted": "report"},
    )
    graph.add_edge("reassess", "verify")
    graph.add_edge("report", END)

    return graph.compile()
