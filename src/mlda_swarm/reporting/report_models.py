"""Structured models used by the cybersecurity Report Agent."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from mlda_swarm.models.finding import Finding


class SeveritySummary(BaseModel):
    """Count findings by severity."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


class SecurityReport(BaseModel):
    """Structured output produced by the Report Agent."""

    run_id: str = Field(
        min_length=1,
        description="Identifier for the cybersecurity swarm run.",
    )

    target_ids: list[str] = Field(
        default_factory=list,
        description="Targets represented in this report.",
    )

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time at which the report was generated.",
    )

    executive_summary: str = Field(
        default="",
        description="Human-readable summary of the assessment.",
    )

    severity_summary: SeveritySummary = Field(
        default_factory=SeveritySummary,
        description="Number of findings at each severity level.",
    )

    findings: list[Finding] = Field(
        default_factory=list,
        description="Validated and deduplicated security findings.",
    )