from mlda_swarm.logging_utils import build_safe_log_event


def test_safe_log_redacts_prompt():
    event = build_safe_log_event(
        run_id="run_001",
        finding_id="finding_001",
        agent_name="report_agent",
        event_type="llm_call",
        prompt="Use password=SuperSecret123",
    )

    assert "SuperSecret123" not in event["prompt"]
    assert "[REDACTED]" in event["prompt"]


def test_safe_log_preserves_ids():
    event = build_safe_log_event(
        run_id="run_001",
        finding_id="finding_123",
        agent_name="report_agent",
        event_type="finding_processed",
    )

    assert event["run_id"] == "run_001"
    assert event["finding_id"] == "finding_123"


def test_safe_log_redacts_tool_call():
    event = build_safe_log_event(
        run_id="run_001",
        agent_name="web_attack_agent",
        event_type="tool_call",
        tool_calls=[
            {
                "tool": "login_test",
                "username": "admin",
                "password": "Secret123",
            }
        ],
    )

    tool_call = event["tool_calls"][0]

    assert tool_call["username"] == "admin"
    assert tool_call["password"] == "[REDACTED]"


def test_safe_log_preserves_metrics():
    event = build_safe_log_event(
        run_id="run_001",
        agent_name="report_agent",
        event_type="llm_call",
        latency_ms=1250.5,
        cost_usd=0.002,
        input_tokens=800,
        output_tokens=250,
    )

    assert event["latency_ms"] == 1250.5
    assert event["cost_usd"] == 0.002
    assert event["input_tokens"] == 800
    assert event["output_tokens"] == 250


def test_safe_log_redacts_error():
    event = build_safe_log_event(
        run_id="run_001",
        agent_name="report_agent",
        event_type="error",
        error="Authentication failed with password=Secret123",
    )

    assert "Secret123" not in event["error"]
    assert "[REDACTED]" in event["error"]