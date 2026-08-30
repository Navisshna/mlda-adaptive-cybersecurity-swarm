from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.markdown_report import (
    render_markdown_report,
    save_markdown_report,
)
from mlda_swarm.reporting.report_generator import (
    build_security_report,
)


def test_render_markdown_report():
    findings = [
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="vulnerability_scanner",
            tool_name="test_scanner",
            title="Outdated Web Server",
            description="An outdated web server was detected.",
            severity="high",
            affected_component="Apache",
            evidence="Apache version is outdated.",
            recommendation="Upgrade Apache.",
            cvss_score=8.1,
            references=["CVE-TEST-001"],
        ),
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="web_attack",
            title="Missing Security Header",
            description="A security header is missing.",
            severity="medium",
            affected_component="/login",
        ),
    ]

    report = build_security_report(
        run_id="run-001",
        findings=findings,
    )

    markdown = render_markdown_report(report)

    assert "# Cybersecurity Assessment Report" in markdown
    assert "run-001" in markdown
    assert "dvwa" in markdown

    assert "**Total Findings:** 2" in markdown
    assert "**High:** 1" in markdown
    assert "**Medium:** 1" in markdown

    assert "Outdated Web Server" in markdown
    assert "Missing Security Header" in markdown

    assert "8.1" in markdown
    assert "Upgrade Apache." in markdown
    assert "CVE-TEST-001" in markdown


def test_save_markdown_report(tmp_path):
    finding = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="recon",
        title="Open HTTP Port",
        description="Port 80 is open.",
        severity="info",
        affected_component="port 80",
    )

    report = build_security_report(
        run_id="run-001",
        findings=[finding],
    )

    output_path = tmp_path / "security_report.md"

    saved_path = save_markdown_report(
        report,
        output_path,
    )

    assert saved_path.exists()

    content = saved_path.read_text(
        encoding="utf-8"
    )

    assert "# Cybersecurity Assessment Report" in content
    assert "Open HTTP Port" in content

def test_markdown_report_redacts_sensitive_evidence():
    finding = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Exposed Credentials",
        description="Credentials were exposed.",
        severity="critical",
        affected_component="/admin",
        evidence="password=SuperSecret123",
        recommendation="Rotate the exposed credentials.",
    )

    report = build_security_report(
        run_id="run-001",
        findings=[finding],
    )

    markdown = render_markdown_report(report)

    # Sensitive value must not appear
    assert "SuperSecret123" not in markdown

    # Redaction marker should appear
    assert "[REDACTED]" in markdown

    # Important report information should remain
    assert "run-001" in markdown
    assert "Exposed Credentials" in markdown
    assert "Critical" in markdown
    assert "/admin" in markdown