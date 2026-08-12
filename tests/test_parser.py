from agents.vulnerability_scanner.parser import parse_nuclei_results
from schemas.finding import Severity


def test_parse_nuclei_result():
    raw_results = [
        {
            "info": {
                "name": "Test Vulnerability",
                "severity": "high",
                "description": "Test finding",
            },
            "matched-at": "http://localhost:4280/test",
        }
    ]

    findings = parse_nuclei_results(raw_results)

    assert len(findings) == 1
    assert findings[0].title == "Test Vulnerability"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].url == "http://localhost:4280/test"
    assert findings[0].source_tool == "nuclei"