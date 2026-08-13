from mlda_swarm.models.finding import Finding
from mlda_swarm.reporting.deduplication import deduplicate_findings


def test_duplicate_findings_are_removed():
    finding_1 = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Missing Security Header",
        description="Security header was not found.",
        severity="medium",
        affected_component="/login",
    )

    finding_2 = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="vulnerability_scanner",
        title="Missing Security Header!",
        description="The security header is missing.",
        severity="medium",
        affected_component="/login/",
    )

    finding_3 = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="recon",
        title="Open HTTP Port",
        description="Port 80 is open.",
        severity="info",
        affected_component="port 80",
    )

    findings = [
        finding_1,
        finding_2,
        finding_3,
    ]

    unique_findings = deduplicate_findings(findings)

    assert len(findings) == 3
    assert len(unique_findings) == 2


def test_same_issue_on_different_components_is_kept():
    finding_1 = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Missing Security Header",
        description="Header missing.",
        severity="medium",
        affected_component="/login",
    )

    finding_2 = Finding(
        run_id="run-001",
        target_id="dvwa",
        agent_name="web_attack",
        title="Missing Security Header",
        description="Header missing.",
        severity="medium",
        affected_component="/admin",
    )

    unique_findings = deduplicate_findings(
        [finding_1, finding_2]
    )

    assert len(unique_findings) == 2


def test_same_issue_on_different_targets_is_kept():
    finding_1 = Finding(
        run_id="run-001",
        target_id="target-a",
        agent_name="web_attack",
        title="Missing Security Header",
        description="Header missing.",
        severity="medium",
        affected_component="/login",
    )

    finding_2 = Finding(
        run_id="run-001",
        target_id="target-b",
        agent_name="web_attack",
        title="Missing Security Header",
        description="Header missing.",
        severity="medium",
        affected_component="/login",
    )

    unique_findings = deduplicate_findings(
        [finding_1, finding_2]
    )

    assert len(unique_findings) == 2