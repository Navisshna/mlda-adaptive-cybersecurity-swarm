from agents.vulnerability_scanner.scanner import run_scan


def print_summary(findings, target_name: str) -> None:
    print(f"Loaded {len(findings)} findings for {target_name}")

    for finding in findings:
        print(f"[{finding.severity.value}] {finding.title} {finding.url}")

    print(
        f"{len(findings)} findings stored "
        f"in outputs/{target_name}_findings.jsonl"
    )


if __name__ == "__main__":
    targets = {
        "dvwa": "http://localhost:4280",
        "juiceshop": "http://localhost:3000",
    }

    for name, url in targets.items():
        findings = run_scan(url, name)
        print_summary(findings, name)
        print()