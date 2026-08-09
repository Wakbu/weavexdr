from langgraph.graph import END, START, StateGraph

from xdr_graph.model_adapter import ModelAdapter, RuleBasedModelAdapter
from xdr_graph.correlation import EventCorrelationEngine
from xdr_graph.detection import DetectionRuleEngine, load_default_detection_engine
from xdr_graph.models import IncidentState
from xdr_graph.nodes import (
    analyze_behavior,
    analyze_file,
    analyze_network,
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
):
    adapter = model_adapter or RuleBasedModelAdapter()
    rules = detection_engine or load_default_detection_engine()
    correlator = correlation_engine or EventCorrelationEngine()
    graph = StateGraph(IncidentState)

    graph.add_node("normalize", normalize_event)
    graph.add_node("file_analysis", lambda state: analyze_file(state, rules))
    graph.add_node("behavior_analysis", lambda state: analyze_behavior(state, rules))
    graph.add_node("network_analysis", lambda state: analyze_network(state, rules))
    graph.add_node("correlate", lambda state: correlate_events(state, correlator))
    graph.add_node("synthesize", lambda state: synthesize_incident(state, adapter))
    graph.add_node("verify", verify_incident)
    graph.add_node("reassess", reassess_incident)
    graph.add_node("report", create_report)

    graph.add_edge(START, "normalize")
    graph.add_edge("normalize", "file_analysis")
    graph.add_edge("normalize", "behavior_analysis")
    graph.add_edge("normalize", "network_analysis")
    graph.add_edge("file_analysis", "correlate")
    graph.add_edge("behavior_analysis", "correlate")
    graph.add_edge("network_analysis", "correlate")
    graph.add_edge("correlate", "synthesize")
    graph.add_edge("synthesize", "verify")
    graph.add_conditional_edges(
        "verify",
        route_after_verification,
        {"revise": "reassess", "accepted": "report"},
    )
    graph.add_edge("reassess", "verify")
    graph.add_edge("report", END)

    return graph.compile()
