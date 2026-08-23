from pydantic import BaseModel, Field

from schemas.finding import Finding


class AgentResult(BaseModel):
    agent_name: str
    status: str
    findings: list[Finding] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
