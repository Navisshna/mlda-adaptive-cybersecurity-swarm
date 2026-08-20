from langgraph.graph import add_messages
from langchain_core.messages import BaseMessage
from typing import Annotated

from typing import List, Literal, Optional, TypedDict
 
from pydantic import BaseModel, Field
 

 
TargetType = Literal[
    "web_app", "api", "embedded_system", "codebase", "network_service"
]
 
Connectivity = Literal[
    "internet_facing", "internal", "offline", "containerised"
]
 
# HIPAA: Health/medical data handling
# PDPA:  General personal data handling
# PCI_DSS: Payment card / financial data handling
RegulatoryFlag = Literal["HIPAA", "PDPA", "PCI_DSS"]
 
# standard: Simple Python process, no isolation
# sandbox:  Agents run inside an isolated Docker container
# privacy:  Standard process, but findings get PII redaction + LOCAL LLM
# air_gap:  No internet access at all
ExecutionMode = Literal["standard", "privacy", "air_gap", "sandbox"]
 
 
# --- Profiler output contract ----------------------------------------------
 
class DataSensitivity(BaseModel):
    """Data sensitivity assessment for a target."""
 
    handles_pii: bool = Field(
        description="Target stores or processes personally identifiable information."
    )
    handles_credentials: bool = Field(
        description="Target stores or processes authentication credentials."
    )
    handles_financial_data: bool = Field(
        description="Target stores or processes financial/payment data."
    )
    handles_health_records: bool = Field(
        description="Target stores or processes health/medical records."
    )
 
 
class TargetProfile(BaseModel):
    """Structured output of the Profiler Agent.
 
    One instance is produced per scan target and consumed by the mode-selection
    step to choose an ExecutionMode. Because the Recon Agent has been folded
    into the Profiler, this profile also carries the deep-recon evidence trail
    in `notes`.
    """
 
    target_id: str = Field(description="Stable identifier for this target within a run.")
    raw_input: str = Field(description="Original input supplied by the user (URL, IP, path, etc).")
    target_type: TargetType = Field(description="Classification of the target system type.")
    connectivity: Connectivity = Field(description="Network reachability posture of the target.")
    
    #--------------------------------user provide---------------
    data_sensitivity: DataSensitivity = Field(description="Structured data sensitivity assessment.")
    regulatory_flags: List[RegulatoryFlag] = Field(
        default_factory=list,
        description="Regulatory regimes the target appears to fall under, if any.",
    )
    #--------------------------------------------------------------
    recommended_mode: ExecutionMode = Field(
        description="Execution mode the Profiler recommends the Orchestrator activate."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Profiler's confidence in this classification (0.0-1.0). "
        "Low-confidence profiles push mode selection toward more isolation.",
    )
    is_blocked: bool = Field(
        default=False,
        description="Flag indicating if the target input was blocked due to malicious patterns.",
    )
    block_reason: Optional[str] = Field(
        default=None,
        description="Detailed explanation if the input was blocked.",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Free-text reasoning trail from the Profiler, including a "
        "summary of the deep-recon evidence gathered.",
    )


# --- LangGraph state --------------------------------------------------------

class ProfilerState(TypedDict, total=False):
    raw_input: str
    declared_sensitivity: DataSensitivity
    declared_regulatory: List[RegulatoryFlag]
    target_id: str
    #for LLM
    messages: Annotated[list[BaseMessage], add_messages]
    profile: Optional[TargetProfile]

    #retry 
    retry : int

    #blocking
    is_blocked: Optional[bool]
    block_reason: Optional[str]




