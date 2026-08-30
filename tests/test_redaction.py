from mlda_swarm.reporting.redaction import redact_text, sanitize_data

def test_password_redaction():
    text = "password=SuperSecret123"

    safe, detected = redact_text(text)

    assert "SuperSecret123" not in safe
    assert "[REDACTED]" in safe
    assert "password" in detected


def test_bearer_token_redaction():
    text = "Authorization: Bearer abc123xyz"

    safe, detected = redact_text(text)

    assert "abc123xyz" not in safe
    assert "[REDACTED]" in safe
    assert "bearer_token" in detected


def test_structured_sensitive_fields():
    data = {
        "username": "admin",
        "password": "Secret123",
        "api_key": "abc123",
    }

    safe, detected = sanitize_data(data)

    assert safe["username"] == "admin"
    assert safe["password"] == "[REDACTED]"
    assert safe["api_key"] == "[REDACTED]"

    assert "Secret123" not in str(safe)
    assert "abc123" not in str(safe)


def test_nested_sensitive_data():
    data = {
        "evidence": {
            "session_token": "very-secret-session-token"
        }
    }

    safe, _ = sanitize_data(data)

    assert (
        safe["evidence"]["session_token"]
        == "[REDACTED]"
    )


def test_run_and_finding_ids_are_preserved():
    data = {
        "run_id": "run_20260823_001",
        "finding_id": "finding_123",
        "password": "Secret123",
    }

    safe, _ = sanitize_data(data)

    assert safe["run_id"] == "run_20260823_001"
    assert safe["finding_id"] == "finding_123"

    assert safe["password"] == "[REDACTED]"


def test_security_finding_data_is_preserved():
    data = {
        "run_id": "run_001",
        "finding_id": "finding_001",
        "cve": "CVE-2021-41773",
        "port": 443,
        "service": "Apache",
        "cvss_score": 9.8,
    }

    safe, detected = sanitize_data(data)

    assert safe == data
    assert detected == []