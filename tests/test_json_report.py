import json

from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.json_report import (
    render_json_report,
    save_json_report,
)
from mlda_swarm.reporting.report_generator import (
    build_security_report,
)


def test_render_json_report():
    finding = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="vulnerability_scanner",
        title="Outdated Web Server",
        description="An outdated web server was detected.",
        severity="high",
        affected_component="Apache",
        evidence="Apache version is outdated.",
        recommendation="Upgrade Apache.",
        cvss_score=8.1,
    )

    report = build_security_report(
        run_id="run-001",
        findings=[finding],
    )

    json_text = render_json_report(report)

    data = json.loads(json_text)

    assert data["run_id"] == "run-001"
    assert data["severity_summary"]["high"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Outdated Web Server"


def test_json_report_redacts_sensitive_data():
    finding = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Exposed Credentials",
        description="Credentials were exposed.",
        severity="critical",
        affected_component="/admin",
        evidence="password=SuperSecret123",
    )

    report = build_security_report(
        run_id="run-001",
        findings=[finding],
    )

    json_text = render_json_report(report)

    assert "SuperSecret123" not in json_text
    assert "[REDACTED]" in json_text

    data = json.loads(json_text)

    # run_id must remain
    assert data["run_id"] == "run-001"

    # finding_id must remain
    assert data["findings"][0]["finding_id"]

    # useful security information must remain
    assert data["findings"][0]["title"] == "Exposed Credentials"
    assert data["findings"][0]["severity"] == "critical"

def test_save_json_report(tmp_path):
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

    output_path = tmp_path / "report.json"

    saved_path = save_json_report(
        report,
        output_path,
    )

    assert saved_path.exists()

    data = json.loads(
        saved_path.read_text(encoding="utf-8")
    )

    assert data["run_id"] == "run-001"
    assert data["findings"][0]["title"] == "Open HTTP Port"