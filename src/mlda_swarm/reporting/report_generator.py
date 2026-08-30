"""Deterministic generation of structured cybersecurity reports."""
from typing import Any

from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.redaction import sanitize_data
from mlda_swarm.logging_utils import log_event
from mlda_swarm.reporting.report_models import (
    SecurityReport,
    SeveritySummary,
)

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def build_severity_summary(
    findings: list[Finding],
) -> SeveritySummary:
    """Count findings by severity."""

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        counts[finding.severity] += 1

    return SeveritySummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        total=len(findings),
    )


def sort_findings_by_severity(
    findings: list[Finding],
) -> list[Finding]:
    """Sort findings from highest to lowest severity."""

    return sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER[finding.severity],
    )


def build_security_report(
    run_id: str,
    findings: list[Finding],
) -> SecurityReport:
    """Build a structured cybersecurity report.

    Args:
        run_id: Identifier for the swarm assessment run.
        findings: Validated and deduplicated findings.

    Returns:
        Structured SecurityReport object.

    Raises:
        ValueError: If a finding belongs to another run.
    """

    log_event(
        run_id=run_id,
        agent_name="reporting",
        event_type="report_generation_started",
        decision=f"Building report from {len(findings)} findings.",
    )

    for finding in findings:
        if finding.run_id != run_id:
            log_event(
                run_id=run_id,
                finding_id=str(finding.finding_id),
                agent_name="reporting",
                event_type="report_generation_error",
                error="Finding run_id does not match report run_id.",
            )

            raise ValueError(
                "Finding run_id does not match the report run_id."
            )

    target_ids = sorted(
        {finding.target_id for finding in findings}
    )

    severity_summary = build_severity_summary(findings)

    sorted_findings = sort_findings_by_severity(findings)

    report = SecurityReport(
        run_id=run_id,
        target_ids=target_ids,
        severity_summary=severity_summary,
        findings=sorted_findings,
    )

    log_event(
        run_id=run_id,
        agent_name="reporting",
        event_type="report_generation_completed",
        decision=f"Structured report created with {len(findings)} findings.",
    )

    return report

def build_safe_report_data(
    report: SecurityReport,
) -> dict[str, Any]:
    """Create a sanitized report copy for external output.

    The original SecurityReport is not modified.
    """

    report_data = report.model_dump(mode="json")

    safe_data, detected = sanitize_data(report_data)

    log_event(
        run_id=report.run_id,
        agent_name="reporting",
        event_type="report_sanitized",
        decision=(
            f"Prepared report for export. "
            f"Redaction types detected: {len(detected)}."
        ),
    )

    return safe_data