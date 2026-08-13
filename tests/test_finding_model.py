"""Tests for the shared security Finding model."""

import pytest
from pydantic import ValidationError

from mlda_swarm.models.finding import Finding


def test_valid_finding_is_accepted() -> None:
    """A correctly structured finding should be accepted."""

    finding = Finding(
        run_id="run-001",
        target_id="dvwa-local",
        agent_name="recon",
        tool_name="nmap",
        title="Open HTTP port",
        description="Port 80 is open and running an HTTP service.",
        severity="info",
        affected_component="dvwa:80",
        evidence="80/tcp open http",
    )

    assert finding.run_id == "run-001"
    assert finding.agent_name == "recon"
    assert finding.severity == "info"
    assert finding.finding_id


def test_invalid_severity_is_rejected() -> None:
    """A severity outside the permitted values should be rejected."""

    with pytest.raises(ValidationError):
        Finding(
            run_id="run-001",
            target_id="dvwa-local",
            agent_name="recon",
            title="Open HTTP port",
            description="Port 80 is open.",
            severity="dangerous",
            affected_component="dvwa:80",
        )


def test_invalid_cvss_score_is_rejected() -> None:
    """A CVSS score must be between 0.0 and 10.0."""

    with pytest.raises(ValidationError):
        Finding(
            run_id="run-001",
            target_id="dvwa-local",
            agent_name="vulnerability_scanner",
            title="Test vulnerability",
            description="This is a test vulnerability.",
            severity="high",
            affected_component="dvwa",
            cvss_score=15.0,
        )


def test_missing_required_field_is_rejected() -> None:
    """A finding without a required title should be rejected."""

    with pytest.raises(ValidationError):
        Finding(
            run_id="run-001",
            target_id="dvwa-local",
            agent_name="recon",
            description="Port 80 is open.",
            severity="info",
            affected_component="dvwa:80",
        )


def test_unexpected_field_is_rejected() -> None:
    """Misspelled or unexpected fields should not be accepted."""

    with pytest.raises(ValidationError):
        Finding(
            run_id="run-001",
            target_id="dvwa-local",
            agent_name="recon",
            title="Open HTTP port",
            description="Port 80 is open.",
            severity="info",
            affected_component="dvwa:80",
            unknown_field="unexpected value",
        )