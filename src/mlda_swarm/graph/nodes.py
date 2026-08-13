"""LangGraph nodes for validating and storing security findings."""

from mlda_swarm.graph.state import FindingsState
from mlda_swarm.models.finding import Finding
from mlda_swarm.storage.findings_store import FindingsStore
from mlda_swarm.reporting.deduplication import deduplicate_findings


def save_findings_node(state: FindingsState) -> dict[str, int]:
    """Validate findings and save them in the shared SQLite store.

    Args:
        state: Current LangGraph state containing raw finding dictionaries.

    Returns:
        State update containing the number of stored findings.

    Raises:
        ValueError: If a finding belongs to a different run.
        pydantic.ValidationError: If a finding has an invalid structure.
    """

    validated_findings = [
        Finding.model_validate(raw_finding)
        for raw_finding in state.get("findings", [])
    ]

    for finding in validated_findings:
        if finding.run_id != state["run_id"]:
            raise ValueError(
                "Finding run_id does not match the LangGraph run_id."
            )

    store = FindingsStore(state["database_path"])
    store.initialise()
    store.add_findings(validated_findings)

    return {
        "stored_finding_count": len(validated_findings),
    }
def deduplicate_findings_node(state: FindingsState) -> dict:
    """Load stored findings and remove duplicates.

    Args:
        state: Current LangGraph state.

    Returns:
        State update containing deduplicated findings
        and the number of unique findings.
    """

    store = FindingsStore(state["database_path"])
    store.initialise()

    findings = store.get_findings_by_run(state["run_id"])

    unique_findings = deduplicate_findings(findings)

    return {
        "deduplicated_findings": [
            finding.model_dump(mode="json")
            for finding in unique_findings
        ],
        "unique_finding_count": len(unique_findings),
    }