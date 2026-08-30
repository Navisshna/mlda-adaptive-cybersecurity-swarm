"""Markdown rendering for cybersecurity assessment reports."""

from pathlib import Path

from mlda_swarm.reporting.report_models import SecurityReport
from mlda_swarm.reporting.report_generator import build_safe_report_data


def render_markdown_report(report: SecurityReport) -> str:
    """Convert a structured SecurityReport into Markdown."""
    safe_data = build_safe_report_data(report)
    report = SecurityReport.model_validate(safe_data)

    lines: list[str] = []

    # Title
    lines.append("# Cybersecurity Assessment Report")
    lines.append("")

    # Assessment information
    lines.append("## Assessment Information")
    lines.append("")
    lines.append(f"- **Run ID:** {report.run_id}")

    targets = ", ".join(report.target_ids) if report.target_ids else "None"
    lines.append(f"- **Target(s):** {targets}")

    lines.append(
        f"- **Generated At:** {report.generated_at.isoformat()}"
    )
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")

    if report.executive_summary:
        lines.append(report.executive_summary)
    else:
        lines.append(
            "Executive summary has not yet been generated."
        )

    lines.append("")

    # Severity summary
    summary = report.severity_summary

    lines.append("## Severity Summary")
    lines.append("")
    lines.append(f"- **Total Findings:** {summary.total}")
    lines.append(f"- **Critical:** {summary.critical}")
    lines.append(f"- **High:** {summary.high}")
    lines.append(f"- **Medium:** {summary.medium}")
    lines.append(f"- **Low:** {summary.low}")
    lines.append(f"- **Info:** {summary.info}")
    lines.append("")

    # Detailed findings
    lines.append("## Detailed Findings")
    lines.append("")

    if not report.findings:
        lines.append("No security findings were identified.")
        lines.append("")
    else:
        for index, finding in enumerate(report.findings, start=1):
            lines.append(f"### {index}. {finding.title}")
            lines.append("")

            lines.append(
                f"- **Severity:** {finding.severity.capitalize()}"
            )

            cvss = (
                str(finding.cvss_score)
                if finding.cvss_score is not None
                else "Not scored"
            )
            lines.append(f"- **CVSS Score:** {cvss}")

            lines.append(
                f"- **Affected Component:** "
                f"{finding.affected_component}"
            )

            lines.append(
                f"- **Detected By:** {finding.agent_name}"
            )

            if finding.tool_name:
                lines.append(
                    f"- **Tool:** {finding.tool_name}"
                )

            lines.append("")

            lines.append("**Description**")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            lines.append("**Evidence**")
            lines.append("")

            if finding.evidence:
                lines.append(finding.evidence)
            else:
                lines.append("No additional evidence provided.")

            lines.append("")

            lines.append("**Recommendation**")
            lines.append("")

            if finding.recommendation:
                lines.append(finding.recommendation)
            else:
                lines.append(
                    "No remediation recommendation provided."
                )

            if finding.references:
                lines.append("")
                lines.append("**References**")
                lines.append("")

                for reference in finding.references:
                    lines.append(f"- {reference}")

            lines.append("")

    return "\n".join(lines)


def save_markdown_report(
    report: SecurityReport,
    output_path: str | Path,
) -> Path:
    """Render and save a SecurityReport as a Markdown file."""

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    markdown = render_markdown_report(report)

    output_path.write_text(
        markdown,
        encoding="utf-8",
    )

    return output_path