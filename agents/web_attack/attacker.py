from concurrent.futures import ThreadPoolExecutor

from schemas.finding import Finding, Severity
from schemas.web_attack import WebAttackInput
from tools.dalfox import run_dalfox
from tools.sqlmap import run_sqlmap


def run_sql_injection_test(
    target_url: str,
    cookie: str | None,
) -> list[Finding]:
    """Run SQLMap and convert SQL injection detections into findings."""

    try:
        output = run_sqlmap(target_url, cookie)
    except Exception:
        return []

    if "is vulnerable" not in output:
        return []

    return [
        Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            url=str(target_url),
            source_tool="sqlmap",
            description="SQLMap detected an injectable parameter.",
        )
    ]


def run_xss_test(
    target_url: str,
    cookie: str | None,
) -> list[Finding]:
    """Run Dalfox and convert XSS detections into findings."""

    try:
        output = run_dalfox(target_url, cookie)
    except Exception:
        return []

    if "XSS found 0 XSS" in output:
        return []

    if "XSS found" not in output:
        return []

    return [
        Finding(
            title="Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            url=str(target_url),
            source_tool="dalfox",
            description="Dalfox detected a potential XSS vulnerability.",
        )
    ]


def run_web_attack(
    target_url: str,
    cookie: str | None = None,
) -> list[Finding]:
    """Validate input, then run SQLMap and Dalfox concurrently."""

    validated_input = WebAttackInput(
        target_url=target_url,
        cookie=cookie,
    )

    validated_url = str(validated_input.target_url)

    with ThreadPoolExecutor(max_workers=2) as executor:
        sql_future = executor.submit(
            run_sql_injection_test,
            validated_url,
            validated_input.cookie,
        )

        xss_future = executor.submit(
            run_xss_test,
            validated_url,
            validated_input.cookie,
        )

        findings = []
        findings.extend(sql_future.result())
        findings.extend(xss_future.result())

    return findings
