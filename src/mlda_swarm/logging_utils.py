from __future__ import annotations

import json
import logging
from typing import Any

from mlda_swarm.reporting.redaction import sanitize_data

def build_safe_log_event(
    *,
    run_id: str,
    agent_name: str,
    event_type: str,
    finding_id: str | None = None,
    prompt: str | None = None,
    tool_calls: list[Any] | None = None,
    latency_ms: float | None = None,
    error: str | None = None,
    cost_usd: float | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """
    Build a structured agent log and redact sensitive data
    before it is printed or stored.
    """

    event = {
        "run_id": run_id,
        "finding_id": finding_id,
        "agent_name": agent_name,
        "event_type": event_type,
        "prompt": prompt,
        "tool_calls": tool_calls or [],
        "latency_ms": latency_ms,
        "error": error,
        "cost_usd": cost_usd,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "decision": decision,
    }

    safe_event, detected = sanitize_data(event)

    safe_event["redactions"] = detected

    return safe_event

LOGGER_NAME = "mlda_swarm"


def get_logger() -> logging.Logger:
    """
    Return the shared MLDA Swarm logger.
    """

    logger = logging.getLogger(LOGGER_NAME)

    if not logger.handlers:
        handler = logging.StreamHandler()

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)

    return logger

def log_event(
    *,
    run_id: str,
    agent_name: str,
    event_type: str,
    finding_id: str | None = None,
    prompt: str | None = None,
    tool_calls: list[Any] | None = None,
    latency_ms: float | None = None,
    error: str | None = None,
    cost_usd: float | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    decision: str | None = None,
    level: int = logging.INFO,
) -> dict[str, Any]:
    """
    Safely log an agent event.

    Sensitive values are sanitized before logging.
    """

    safe_event = build_safe_log_event(
        run_id=run_id,
        finding_id=finding_id,
        agent_name=agent_name,
        event_type=event_type,
        prompt=prompt,
        tool_calls=tool_calls,
        latency_ms=latency_ms,
        error=error,
        cost_usd=cost_usd,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        decision=decision,
    )

    logger = get_logger()

    logger.log(
        level,
        json.dumps(
            safe_event,
            ensure_ascii=False,
            default=str,
        ),
    )

    return safe_event