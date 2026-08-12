"""
Environment Manager Agent
--------------------------
Consumes the Target Profile produced by the Profiler Agent (passed on via
the Orchestrator) and provisions the runtime the specialist agent swarm
executes inside, matching the recommended execution mode.

Upstream contract (from Profiler schema, pydantic-based):
    target_id: str
    raw_input: str
    target_type: Literal["web_app","api","embedded_system","codebase","network_service"]
    connectivity: Literal["internet_facing","internal","offline","containerised"]
    data_sensitivity: DataSensitivity
    regulatory_flags: list[Literal["HIPAA","PDPA","PCI_DSS"]]
    recommended_mode: Literal["standard","privacy","air_gap","sandbox"]
    confidence: float          # 0.0 - 1.0
    notes: str | None

Mode definitions (per Profiler schema notes):
    standard  -> simple python process, no isolation
    sandbox   -> agents run inside an isolated Docker container
    privacy   -> standard process, but findings get PII-pattern redaction
                 before hitting the findings store
    air_gap   -> agents have no access to the internet
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional
from langchain_ollama import ChatOllama

try:
    import docker
except ImportError:
    # Lets this file be imported/tested even before docker is installed locally.
    docker = None



def get_llm_client(backend: str):
    """Factory so specialist agents get a real, working LLM object,
    not just a string to interpret themselves."""
    if backend == "ollama":
        return ChatOllama(
            model="llama3.1:8b",
            base_url="http://localhost:11434",
            temperature=0.2,
        )
    elif backend == "grok":
        raise NotImplementedError("wire up existing grok client here")
    else:
        raise ValueError(f"Unknown llm_backend: {backend}")


def _ollama_is_reachable(base_url: str = "http://localhost:11434") -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(base_url, timeout=2)
        return True
    except Exception:
        return False
    
ExecutionMode = Literal["standard", "privacy", "air_gap", "sandbox"]

# Below this confidence, the Profiler itself said it prefers to fall back
# to more isolation rather than trust its own classification.
LOW_CONFIDENCE_THRESHOLD = 0.5


@dataclass
class ProvisionResult:
    mode: ExecutionMode
    network_id: Optional[str]
    llm_backend: str          # "grok" (cloud) or "ollama" (local)
    internet_allowed: bool
    notes: str = ""


class EnvironmentManager:
    """Builds and tears down the isolated runtime for the specialist swarm."""

    def __init__(self):
        self.client = docker.from_env() if docker else None
        self._active_network = None

    def provision(self, target_profile: dict) -> ProvisionResult:
        mode: ExecutionMode = target_profile["recommended_mode"]
        confidence: float = target_profile.get("confidence", 0.0)

        # Safety fallback: low-confidence classification should not run
        # in a less-isolated mode than sandbox.
        if confidence < LOW_CONFIDENCE_THRESHOLD and mode == "standard":
            mode = "sandbox"

        if mode == "standard":
            return self._standard()
        elif mode == "sandbox":
            return self._sandbox()
        elif mode == "privacy":
            return self._privacy()
        elif mode == "air_gap":
            return self._air_gap()
        else:
            raise ValueError(f"Unknown execution mode: {mode}")

    def _standard(self) -> ProvisionResult:
        return ProvisionResult(
            mode="standard", network_id=None,
            llm_backend="grok", internet_allowed=True,
        )

    def _sandbox(self) -> ProvisionResult:
        net = self.client.networks.create("swarm-sandbox", driver="bridge", internal=False)
        self._active_network = net
        return ProvisionResult(
            mode="sandbox", network_id=net.id,
            llm_backend="grok", internet_allowed=True,
        )

    def _privacy(self) -> ProvisionResult:
        net = self.client.networks.create("swarm-privacy", driver="bridge", internal=False)
        self._active_network = net
        if not _ollama_is_reachable():
            net.remove()
            raise RuntimeError("privacy mode requires Ollama running locally, but it's unreachable")
        return ProvisionResult(
            mode="privacy", network_id=net.id,
            llm_backend="ollama", internet_allowed=True,
            notes="findings must be PII-redacted before hitting the findings store",
        )

    def _air_gap(self) -> ProvisionResult:
        net = self.client.networks.create("swarm-airgap", driver="bridge", internal=True)
        self._active_network = net
        if not _ollama_is_reachable():
            net.remove()
            raise RuntimeError("air_gap mode requires Ollama running locally, but it's unreachable — no fallback available")
        return ProvisionResult(
            mode="air_gap", network_id=net.id,
            llm_backend="ollama", internet_allowed=False,
        )

    def teardown(self):
        if self._active_network:
            self._active_network.remove()
            self._active_network = None


if __name__ == "__main__":
    # Mock Target Profile matching Darren's exact schema, so this can be
    # tested against a realistic input before his agent is finished.
    mock_profile = {
        "target_id": "test-001",
        "raw_input": "http://localhost:8080",
        "target_type": "web_app",
        "connectivity": "internet_facing",
        "data_sensitivity": "low",
        "regulatory_flags": [],
        "recommended_mode": "air_gap",
        "confidence": 0.3,
        "notes": "DVWA test instance",
    }

    mgr = EnvironmentManager()
    result = mgr.provision(mock_profile)
    print(result)
    if result.llm_backend == "ollama":
        llm = get_llm_client(result.llm_backend)
        test_response = llm.invoke("Say 'agent online' if you can read this.")
        print("LLM test:", test_response.content)
    mgr.teardown()