from langgraph.graph import END, START, StateGraph

from xdr_graph.model_adapter import ModelAdapter, RuleBasedModelAdapter
from xdr_graph.models import IncidentState
from xdr_graph.nodes import (
    analyze_behavior,
    analyze_file,
    analyze_network,
    create_report,
    normalize_event,
    reassess_incident,
    route_after_verification,
    synthesize_incident,
    verify_incident,
)


def build_workflow(model_adapter: ModelAdapter | None = None):
    adapter = model_adapter or RuleBasedModelAdapter()
    graph = StateGraph(IncidentState)

    graph.add_node("normalize", normalize_event)
    graph.add_node("file_analysis", analyze_file)
    graph.add_node("behavior_analysis", analyze_behavior)
    graph.add_node("network_analysis", analyze_network)
    graph.add_node("synthesize", lambda state: synthesize_incident(state, adapter))
    graph.add_node("verify", verify_incident)
    graph.add_node("reassess", reassess_incident)
    graph.add_node("report", create_report)

    graph.add_edge(START, "normalize")
    graph.add_edge("normalize", "file_analysis")
    graph.add_edge("normalize", "behavior_analysis")
    graph.add_edge("normalize", "network_analysis")
    graph.add_edge("file_analysis", "synthesize")
    graph.add_edge("behavior_analysis", "synthesize")
    graph.add_edge("network_analysis", "synthesize")
    graph.add_edge("synthesize", "verify")
    graph.add_conditional_edges(
        "verify",
        route_after_verification,
        {"revise": "reassess", "accepted": "report"},
    )
    graph.add_edge("reassess", "verify")
    graph.add_edge("report", END)

    return graph.compile()
