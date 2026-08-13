"""LangGraph workflow for validating and storing findings."""

from langgraph.graph import END, START, StateGraph

from mlda_swarm.graph.nodes import (
    deduplicate_findings_node,
    save_findings_node,
)
from mlda_swarm.graph.state import FindingsState


def build_findings_workflow():
    """Build and compile the findings-storage workflow."""

    builder = StateGraph(FindingsState)

    builder.add_node("save_findings", save_findings_node)
    builder.add_node(
    "deduplicate_findings",
    deduplicate_findings_node,
)

    builder.add_edge(START, "save_findings")
    builder.add_edge(
    "save_findings",
    "deduplicate_findings",
)
    builder.add_edge(
    "deduplicate_findings",
    END,
) 

    return builder.compile()