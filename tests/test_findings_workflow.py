from mlda_swarm.graph.workflow import build_findings_workflow
from mlda_swarm.storage.findings_store import FindingsStore


def test_findings_workflow_deduplicates(tmp_path):
    database_path = tmp_path / "findings.db"

    workflow = build_findings_workflow()

    initial_state = {
        "run_id": "run-001",
        "database_path": str(database_path),
        "findings": [
            {
                "run_id": "run-001",
                "target_id": "dvwa",
                "agent_name": "web_attack",
                "title": "Missing Security Header",
                "description": "Security header was not found.",
                "severity": "medium",
                "affected_component": "/login",
            },
            {
                "run_id": "run-001",
                "target_id": "dvwa",
                "agent_name": "vulnerability_scanner",
                "title": "Missing Security Header!",
                "description": "The same security header is missing.",
                "severity": "medium",
                "affected_component": "/login/",
            },
            {
                "run_id": "run-001",
                "target_id": "dvwa",
                "agent_name": "recon",
                "title": "Open HTTP Port",
                "description": "Port 80 is open.",
                "severity": "info",
                "affected_component": "port 80",
            },
        ],
    }

    result = workflow.invoke(initial_state)

    assert result["stored_finding_count"] == 3
    assert result["unique_finding_count"] == 2
    assert len(result["deduplicated_findings"]) == 2

    # Raw database should still contain all 3 findings.
    store = FindingsStore(database_path)
    stored_findings = store.get_findings_by_run("run-001")

    assert len(stored_findings) == 3