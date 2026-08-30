from mlda_swarm.reporting.pdf_report import (
    compile_latex_to_pdf,
)
from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.json_report import save_json_report
from mlda_swarm.reporting.latex_report import render_latex_from_json
from mlda_swarm.reporting.report_generator import build_security_report


def main():
    findings = [
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="web_attack",
            tool_name="test_scanner",
            title="Exposed Administrator Credentials",
            description=(
                "Administrator credentials were exposed "
                "during the assessment."
            ),
            severity="critical",
            affected_component="/admin",
            evidence="password=SuperSecret123",
            recommendation=(
                "Rotate the exposed credentials and "
                "review authentication controls."
            ),
            cvss_score=9.8,
            references=["CVE-TEST-001"],
        ),
        Finding(
            run_id="run-001",
            target_id="dvwa",
            agent_name="vulnerability_scanner",
            tool_name="test_scanner",
            title="Outdated Web Server",
            description="An outdated Apache version was detected.",
            severity="high",
            affected_component="Apache",
            evidence="Apache version 2.4.x is outdated.",
            recommendation="Upgrade Apache to a patched version.",
            cvss_score=8.1,
        ),
    ]

    report = build_security_report(
        run_id="run-001",
        findings=findings,
    )

    json_path = save_json_report(
        report,
        "output/report.json",
    )

    tex_path = render_latex_from_json(
        json_path,
        "output/generated_report.tex",
    )

    pdf_path = compile_latex_to_pdf(
    tex_path=tex_path,
    output_dir="output",
    run_id="run-001",
    )

    print(f"JSON report: {json_path}")
    print(f"LaTeX report: {tex_path}")
    print(f"PDF report: {pdf_path}")

if __name__ == "__main__":
    main()