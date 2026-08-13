"""Shared data model for security findings produced by specialist agents."""

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]


class Finding(BaseModel):
    """Represent one validated security finding."""

    # Reject unexpected or misspelled fields.
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for the finding.",
    )

    run_id: str = Field(
        min_length=1,
        description="Identifier for the complete swarm run.",
    )

    target_id: str = Field(
        min_length=1,
        description="Identifier for the target being assessed.",
    )

    agent_name: str = Field(
        min_length=1,
        description="Agent that produced the finding.",
    )

    tool_name: str | None = Field(
        default=None,
        description="Tool that produced the evidence.",
    )

    title: str = Field(
        min_length=1,
        description="Short title describing the finding.",
    )

    description: str = Field(
        min_length=1,
        description="Detailed explanation of the finding.",
    )

    severity: Severity = Field(
        default="info",
        description="Severity classification.",
    )

    affected_component: str = Field(
        min_length=1,
        description="Affected port, URL, service, or component.",
    )

    evidence: str | None = Field(
        default=None,
        description="Evidence or tool output supporting the finding.",
    )

    recommendation: str | None = Field(
        default=None,
        description="Recommended remediation.",
    )

    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS score from 0.0 to 10.0.",
    )

    references: list[str] = Field(
        default_factory=list,
        description="Relevant references such as CVE identifiers.",
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time at which the finding was created.",
    )