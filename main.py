"""
Entry point for the Vulnerability Scanner Agent.

Runs Nuclei against configured targets, normalizes the results,
stores them as JSONL, and prints a human-readable summary.
"""

from pathlib import Path

from scanner.models import Finding
from scanner.nuclei import run_nuclei
from scanner.parser import parse_nuclei_results, save_findings


def run_scan(target_url: str, target_name: str) -> list[Finding]:
    """Run the complete vulnerability scanning pipeline for a target."""

    raw_results = run_nuclei(target_url, target_name)

    findings = parse_nuclei_results(raw_results)

    output_path = Path(f"outputs/{target_name}_findings.jsonl")
    save_findings(findings, output_path)

    return findings


def print_summary(findings: list[Finding], target_name: str) -> None:
    """Display scan results in a readable format."""

    print(f"Loaded {len(findings)} findings for {target_name}")

    for finding in findings:
        print(
            f"[{finding.severity.value}] "
            f"{finding.title} "
            f"{finding.url}"
        )

    print(
        f"{len(findings)} findings stored in "
        f"outputs/{target_name}_findings.jsonl"
    )


if __name__ == "__main__":

    TARGETS = {
        "dvwa": "http://localhost:4280",
        "juiceshop": "http://localhost:3000",
    }

    for target_name, target_url in TARGETS.items():

        findings = run_scan(target_url, target_name)

        print_summary(findings, target_name)

        print()