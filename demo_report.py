from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.markdown_report import (
    save_markdown_report,
)
from mlda_swarm.reporting.report_generator import (
    build_security_report,
)


findings = [
    Finding(
        run_id="demo-run-001",
        target_id="demo-web-app",
        agent_name="vulnerability_scanner",
        tool_name="scanner",
        title="Outdated Web Server",
        description=(
            "The target is running an outdated "
            "web server version."
        ),
        severity="high",
        affected_component="Web server",
        evidence="Outdated version detected.",
        recommendation=(
            "Upgrade the web server to a "
            "currently supported version."
        ),
        cvss_score=8.0,
    ),
    Finding(
        run_id="demo-run-001",
        target_id="demo-web-app",
        agent_name="web_attack",
        title="Missing Security Header",
        description=(
            "A recommended HTTP security "
            "header was not present."
        ),
        severity="medium",
        affected_component="/login",
        recommendation=(
            "Configure the required HTTP "
            "security header."
        ),
    ),
]

report = build_security_report(
    run_id="demo-run-001",
    findings=findings,
)

path = save_markdown_report(
    report,
    "output/demo-run-001/security_report.md",
)

print(f"Report created: {path}")