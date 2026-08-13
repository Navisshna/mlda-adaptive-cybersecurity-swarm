"""Simple demonstration of the shared Finding model."""

from mlda_swarm.models.finding import Finding


finding = Finding(
    run_id="run-001",
    target_id="dvwa-local",
    agent_name="recon",
    tool_name="nmap",
    title="Open HTTP port",
    description="Port 80 is open and running an HTTP service.",
    severity="info",
    affected_component="dvwa:80",
    evidence="80/tcp open http",
)

print(finding.model_dump_json(indent=2))