"""
Tests for the Environment Manager agent.

These are integration tests, not pure unit tests — they talk to a real
local Docker daemon rather than mocking it. That's a deliberate tradeoff:
mocked tests would run without Docker installed, but wouldn't actually
prove isolation/container behavior works. Given this module's whole job
is "does Docker do the right thing," testing against the real daemon is
more meaningful here, at the cost of these tests requiring Docker Desktop
to be running to pass.

Run with: pytest test_environment_manager.py -v
"""

import pytest
from environment_manager import EnvironmentManager


def make_profile(mode: str, confidence: float = 0.9) -> dict:
    """Builds a mock Target Profile matching the Profiler's schema."""
    return {
        "target_id": "test-001",
        "raw_input": "http://localhost:8080",
        "target_type": "web_app",
        "connectivity": "internet_facing",
        "data_sensitivity": "low",
        "regulatory_flags": [],
        "recommended_mode": mode,
        "confidence": confidence,
        "notes": "test profile",
    }


@pytest.fixture
def mgr():
    """Fresh EnvironmentManager per test, with guaranteed teardown even
    if the test itself fails partway through."""
    m = EnvironmentManager()
    yield m
    m.teardown()


def test_standard_mode_creates_no_network(mgr):
    result = mgr.provision(make_profile("standard"))
    assert result.mode == "standard"
    assert result.network_id is None
    assert result.internet_allowed is True


def test_sandbox_mode_creates_network(mgr):
    result = mgr.provision(make_profile("sandbox"))
    assert result.mode == "sandbox"
    assert result.network_id is not None
    assert result.internet_allowed is True


def test_air_gap_network_is_internal(mgr):
    result = mgr.provision(make_profile("air_gap"))
    assert result.mode == "air_gap"
    assert result.internet_allowed is False

    # Confirm isolation is real, not just labeled — check Docker itself.
    network = mgr.client.networks.get(result.network_id)
    assert network.attrs["Internal"] is True


def test_privacy_mode_flags_redaction_note(mgr):
    result = mgr.provision(make_profile("privacy"))
    assert result.mode == "privacy"
    assert "redact" in result.notes.lower()

def test_launch_agent_container_on_active_network(mgr):
    mgr.provision(make_profile("sandbox"))
    container = mgr.launch_agent_container()
    assert container is not None
    # Container should be attached to the network we just created.
    container.reload()
    networks = container.attrs["NetworkSettings"]["Networks"]
    assert mgr._active_network.name in networks


def test_launch_agent_container_without_network_raises():
    m = EnvironmentManager()
    with pytest.raises(RuntimeError):
        m.launch_agent_container()


def test_teardown_removes_network(mgr):
    result = mgr.provision(make_profile("sandbox"))
    network_id = result.network_id
    mgr.teardown()

    with pytest.raises(Exception):
        mgr.client.networks.get(network_id)  # should no longer exist