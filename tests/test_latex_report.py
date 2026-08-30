from mlda_swarm.reporting.latex_report import (
    render_latex_report,
)


def test_render_latex_report():
    report_data = {
        "run_id": "run-001",
        "target_ids": ["dvwa"],
        "generated_at": "2026-08-25T16:00:00",
        "executive_summary": None,

        "severity_summary": {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 1,
        },

        "findings": [
            {
                "finding_id": "finding-001",
                "title": "Exposed Credentials",
                "severity": "critical",
                "cvss_score": 9.8,
                "affected_component": "/admin",
                "agent_name": "web_attack",
                "tool_name": "test_scanner",
                "description": "Credentials were exposed.",
                "evidence": "password=[REDACTED]",
                "recommendation": "Rotate credentials.",
                "references": [],
            }
        ],
    }

    latex = render_latex_report(report_data)

    assert "run-001" in latex
    assert "finding-001" in latex
    assert "Exposed Credentials" in latex
    assert "[REDACTED]" in latex

    # LaTeX special character should be escaped
    assert r"web\_attack" in latex