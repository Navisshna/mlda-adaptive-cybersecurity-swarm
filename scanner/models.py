"""
Shared data models for the Vulnerability Scanner Agent.
"""

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    """Supported vulnerability severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """Normalized representation of a scanner finding."""

    title: str
    severity: Severity
    url: str
    source_tool: str
    description: str | None = None