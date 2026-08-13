"""Tests for the SQLite findings store."""

from pathlib import Path

from mlda_swarm.models.finding import Finding
from mlda_swarm.storage.findings_store import FindingsStore


def create_recon_finding() -> Finding:
    """Create a sample Recon Agent finding."""

    return Finding(
        run_id="run-001",
        target_id="dvwa-local",
        agent_name="recon",
        tool_name="nmap",
        title="Open HTTP port",
        description="Port 80 is open.",
        severity="info",
        affected_component="dvwa:80",
        evidence="80/tcp open http",
    )


def create_vulnerability_finding() -> Finding:
    """Create a sample Vulnerability Scanner finding."""

    return Finding(
        run_id="run-001",
        target_id="dvwa-local",
        agent_name="vulnerability_scanner",
        tool_name="nikto",
        title="Missing security header",
        description="The X-Frame-Options header is missing.",
        severity="low",
        affected_component="DVWA HTTP response",
        evidence="X-Frame-Options header not present",
        recommendation="Configure the server to include the header.",
    )


def test_add_and_retrieve_findings(tmp_path: Path) -> None:
    """Stored findings should be retrievable by run ID."""

    store = FindingsStore(tmp_path / "findings.db")
    store.initialise()

    store.add_findings(
        [
            create_recon_finding(),
            create_vulnerability_finding(),
        ]
    )

    findings = store.get_findings_by_run("run-001")

    assert len(findings) == 2
    assert findings[0].run_id == "run-001"


def test_retrieve_findings_by_agent(tmp_path: Path) -> None:
    """The store should filter findings by agent name."""

    store = FindingsStore(tmp_path / "findings.db")
    store.initialise()

    store.add_findings(
        [
            create_recon_finding(),
            create_vulnerability_finding(),
        ]
    )

    findings = store.get_findings_by_agent(
        run_id="run-001",
        agent_name="recon",
    )

    assert len(findings) == 1
    assert findings[0].agent_name == "recon"
    assert findings[0].tool_name == "nmap"


def test_clear_run(tmp_path: Path) -> None:
    """Clearing a run should remove its stored findings."""

    store = FindingsStore(tmp_path / "findings.db")
    store.initialise()
    store.add_finding(create_recon_finding())

    store.clear_run("run-001")

    findings = store.get_findings_by_run("run-001")

    assert findings == []