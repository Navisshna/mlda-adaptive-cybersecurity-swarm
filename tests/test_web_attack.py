import pytest
from pydantic import ValidationError

from agents.web_attack.attacker import (
    run_sql_injection_test,
    run_xss_test,
    run_web_attack,
)


def test_sql_injection_no_finding(monkeypatch):
    def fake_run_sqlmap(target_url, cookie):
        return "No injection detected"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_sqlmap",
        fake_run_sqlmap,
    )

    findings = run_sql_injection_test(
        "http://localhost:4280/vulnerabilities/sqli/?id=1",
        "PHPSESSID=test; security=low",
    )

    assert findings == []


def test_sql_injection_finding(monkeypatch):
    def fake_run_sqlmap(target_url, cookie):
        return "GET parameter 'id' is vulnerable"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_sqlmap",
        fake_run_sqlmap,
    )

    findings = run_sql_injection_test(
        "http://localhost:4280/vulnerabilities/sqli/?id=1",
        "PHPSESSID=test; security=low",
    )

    assert len(findings) == 1
    assert findings[0].title == "SQL Injection"
    assert findings[0].severity.value == "HIGH"
    assert findings[0].source_tool == "sqlmap"


def test_xss_no_finding(monkeypatch):
    def fake_run_dalfox(target_url, cookie):
        return "XSS found 0 XSS"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_dalfox",
        fake_run_dalfox,
    )

    findings = run_xss_test(
        "http://localhost:4280/vulnerabilities/xss_r/",
        "PHPSESSID=test; security=low",
    )

    assert findings == []


def test_xss_finding(monkeypatch):
    def fake_run_dalfox(target_url, cookie):
        return "XSS found 1 XSS"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_dalfox",
        fake_run_dalfox,
    )

    findings = run_xss_test(
        "http://localhost:4280/vulnerabilities/xss_r/",
        "PHPSESSID=test; security=low",
    )

    assert len(findings) == 1
    assert findings[0].title == "Cross-Site Scripting (XSS)"
    assert findings[0].severity.value == "HIGH"
    assert findings[0].source_tool == "dalfox"


def test_web_attack_runs_both_tools(monkeypatch):
    def fake_run_sqlmap(target_url, cookie):
        return "GET parameter 'id' is vulnerable"

    def fake_run_dalfox(target_url, cookie):
        return "XSS found 1 XSS"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_sqlmap",
        fake_run_sqlmap,
    )

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_dalfox",
        fake_run_dalfox,
    )

    findings = run_web_attack(
        "http://localhost:4280",
        "PHPSESSID=test; security=low",
    )


    assert len(findings.findings) == 2
    assert findings.findings[0].source_tool == "sqlmap"
    assert findings.findings[1].source_tool == "dalfox"


def test_web_attack_accepts_valid_url(monkeypatch):
    def fake_run_sqlmap(target_url, cookie):
        return "No injection detected"

    def fake_run_dalfox(target_url, cookie):
        return "XSS found 0 XSS"

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_sqlmap",
        fake_run_sqlmap,
    )

    monkeypatch.setattr(
        "agents.web_attack.attacker.run_dalfox",
        fake_run_dalfox,
    )

    findings = run_web_attack(
        "http://localhost:4280",
        "PHPSESSID=test; security=low",
    )

    assert findings.findings == []


def test_web_attack_rejects_invalid_url():
    with pytest.raises(ValidationError):
        run_web_attack(
            "not-a-valid-url",
            "PHPSESSID=test",
        )


def test_web_attack_rejects_unsupported_scheme():
    with pytest.raises(ValidationError):
        run_web_attack(
            "ftp://localhost:4280",
            "PHPSESSID=test",
        )
