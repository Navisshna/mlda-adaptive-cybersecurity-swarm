from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    title: str
    severity: Severity
    url: str
    source_tool: str
    description: str | None = None