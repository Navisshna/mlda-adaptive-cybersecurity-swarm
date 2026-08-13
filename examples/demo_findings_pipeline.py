"""Local demonstration of the shared findings pipeline."""

import json
from pathlib import Path

from mlda_swarm.graph.workflow import build_findings_workflow
from mlda_swarm.storage.findings_store import FindingsStore


def main() -> None:
    """Run the mock findings pipeline and display stored findings."""

    database_path = Path("data/demo_findings.db")

    graph = build_findings_workflow()

    result = graph.invoke(
        {
            "run_id": "demo-run-001",
            "database_path": str(database_path),
            "findings": [
                {
                    "run_id": "demo-run-001",
                    "target_id": "dvwa-local",
                    "agent_name": "recon",
                    "tool_name": "nmap",
                    "title": "Open HTTP port",
                    "description": "Port 80 is open.",
                    "severity": "info",
                    "affected_component": "dvwa:80",
                    "evidence": "80/tcp open http",
                },
                {
                    "run_id": "demo-run-001",
                    "target_id": "dvwa-local",
                    "agent_name": "vulnerability_scanner",
                    "tool_name": "nikto",
                    "title": "Missing security header",
                    "description": (
                        "The X-Frame-Options header is missing."
                    ),
                    "severity": "low",
                    "affected_component": "DVWA HTTP response",
                    "evidence": (
                        "X-Frame-Options header not present"
                    ),
                    "recommendation": (
                        "Configure the server to include the header."
                    ),
                },
            ],
        }
    )

    store = FindingsStore(database_path)
    stored_findings = store.get_findings_by_run("demo-run-001")

    output = {
        "run_id": "demo-run-001",
        "stored_finding_count": result["stored_finding_count"],
        "findings": [
            finding.model_dump(mode="json")
            for finding in stored_findings
        ],
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()