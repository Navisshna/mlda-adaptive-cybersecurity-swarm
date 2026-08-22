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
    privacy   -> isolated Docker network + local Ollama; internet allowed;
                 findings flagged for PII-pattern redaction before hitting
                 the findings store
    air_gap   -> agents have no access to the internet

NOTE: Docker is a hard requirement for this module, not optional — every
mode depends on it to actually provision isolation.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional
from langchain_ollama import ChatOllama

import docker  # hard dependency — this module cannot function without it


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
        raise NotImplementedError("wire up existing grok/groq client here — not owned by this module")
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

PLACEHOLDER_AGENT_IMAGE = "alpine:latest"


@dataclass
class ProvisionResult:
    mode: ExecutionMode
    network_id: Optional[str]
    llm_backend: str
    internet_allowed: bool
    notes: str = ""


class EnvironmentManager:
    """Builds and tears down the isolated runtime for the specialist swarm."""

    def __init__(self):
        self.client = docker.from_env()
        self._active_network = None
        self._active_containers: list = []

    def _get_or_create_network(self, name: str, internal: bool):
        """Reuse a leftover network if one already exists under this name
        (e.g. from a previous run that crashed before teardown() ran),
        instead of failing with a 'network already exists' error."""
        existing = self.client.networks.list(names=[name])
        if existing:
            return existing[0]
        return self.client.networks.create(name, driver="bridge", internal=internal)

    def provision(self, target_profile: dict) -> ProvisionResult:
        mode: ExecutionMode = target_profile["recommended_mode"]
        confidence: float = target_profile.get("confidence", 0.0)

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
        net = self._get_or_create_network("swarm-sandbox", internal=False)
        self._active_network = net
        return ProvisionResult(
            mode="sandbox", network_id=net.id,
            llm_backend="grok", internet_allowed=True,
        )

    def _privacy(self) -> ProvisionResult:
        net = self._get_or_create_network("swarm-privacy", internal=False)
        self._active_network = net
        if not _ollama_is_reachable():
            net.remove()
            self._active_network = None
            raise RuntimeError("privacy mode requires Ollama running locally, but it's unreachable")
        return ProvisionResult(
            mode="privacy", network_id=net.id,
            llm_backend="ollama", internet_allowed=True,
            notes="findings must be PII-redacted before hitting the findings store",
        )

    def _air_gap(self) -> ProvisionResult:
        net = self._get_or_create_network("swarm-airgap", internal=True)
        self._active_network = net
        if not _ollama_is_reachable():
            net.remove()
            self._active_network = None
            raise RuntimeError("air_gap mode requires Ollama running locally, but it's unreachable — no fallback available")
        return ProvisionResult(
            mode="air_gap", network_id=net.id,
            llm_backend="ollama", internet_allowed=False,
        )

    def launch_agent_container(self, image: str = PLACEHOLDER_AGENT_IMAGE,
                                command: str = "echo 'agent container online'"):
        if not self._active_network:
            raise RuntimeError("No active network — call provision() with a mode that creates one first")

        container = self.client.containers.run(
            image,
            command=command,
            network=self._active_network.name,
            detach=True,
            remove=True,
        )
        self._active_containers.append(container)
        return container

    def teardown(self):
        for c in self._active_containers:
            try:
                c.stop()
            except Exception:
                pass
        self._active_containers = []

        if self._active_network:
            self._active_network.remove()
            self._active_network = None


if __name__ == "__main__":
    mock_profile = {
        "target_id": "test-001",
        "raw_input": "http://localhost:8080",
        "target_type": "web_app",
        "connectivity": "internet_facing",
        "data_sensitivity": "low",
        "regulatory_flags": [],
        "recommended_mode": "air_gap",
        "confidence": 0.87,
        "notes": "DVWA test instance",
    }

    mgr = EnvironmentManager()
    result = mgr.provision(mock_profile)
    print(result)

    if result.network_id:
        container = mgr.launch_agent_container()
        print("Container launched:", container.name)

    if result.llm_backend == "ollama":
        llm = get_llm_client(result.llm_backend)
        test_response = llm.invoke("Say 'agent online' if you can read this.")
        print("LLM test:", test_response.content)

    mgr.teardown()