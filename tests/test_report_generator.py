from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.report_generator import (
    build_security_report,
)


def test_build_security_report():
    findings = [
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="web_attack",
            title="Missing Security Header",
            description="A security header is missing.",
            severity="medium",
            affected_component="/login",
        ),
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="vulnerability_scanner",
            title="Outdated Web Server",
            description="An outdated web server was detected.",
            severity="high",
            affected_component="Apache",
        ),
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="recon",
            title="Open HTTP Port",
            description="Port 80 is open.",
            severity="info",
            affected_component="port 80",
        ),
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="auth",
            title="Weak Session Configuration",
            description="Session configuration is insecure.",
            severity="critical",
            affected_component="/login",
        ),
        Finding(
            run_id="run-001",
            target_id="api-server",
            agent_name="code_analysis",
            title="Verbose Error Message",
            description="Detailed errors are exposed.",
            severity="low",
            affected_component="/api",
        ),
    ]

    report = build_security_report(
        run_id="run-001",
        findings=findings,
    )

    assert report.run_id == "run-001"

    assert report.severity_summary.total == 5
    assert report.severity_summary.critical == 1
    assert report.severity_summary.high == 1
    assert report.severity_summary.medium == 1
    assert report.severity_summary.low == 1
    assert report.severity_summary.info == 1

    assert report.target_ids == [
        "api-server",
        "dvwa",
    ]

    assert report.findings[0].severity == "critical"
    assert report.findings[1].severity == "high"
    assert report.findings[2].severity == "medium"
    assert report.findings[3].severity == "low"
    assert report.findings[4].severity == "info"

import pytest


def test_report_rejects_wrong_run_id():
    finding = Finding(
        run_id="run-002",
        target_id="dvwa",
        agent_name="web_attack",
        title="Missing Security Header",
        description="A security header is missing.",
        severity="medium",
        affected_component="/login",
    )

    with pytest.raises(
        ValueError,
        match="Finding run_id does not match",
    ):
        build_security_report(
            run_id="run-001",
            findings=[finding],
        )