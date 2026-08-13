from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.report_models import (
    SecurityReport,
    SeveritySummary,
)


def test_security_report_model():
    finding = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Missing Security Header",
        description="A required security header is missing.",
        severity="medium",
        affected_component="/login",
        recommendation="Configure the missing security header.",
    )

    summary = SeveritySummary(
        critical=0,
        high=0,
        medium=1,
        low=0,
        info=0,
        total=1,
    )

    report = SecurityReport(
        run_id="run-001",
        target_ids=["dvwa"],
        executive_summary="One medium-severity finding was identified.",
        severity_summary=summary,
        findings=[finding],
    )

    assert report.run_id == "run-001"
    assert report.target_ids == ["dvwa"]
    assert report.severity_summary.total == 1
    assert report.severity_summary.medium == 1
    assert len(report.findings) == 1
    assert report.findings[0].title == "Missing Security Header"