"""Shared LangGraph state for the findings pipeline."""

from typing import Any

from typing_extensions import NotRequired, TypedDict


class FindingsState(TypedDict):
    """State passed between nodes in the findings workflow."""

    run_id: str
    database_path: str
    findings: list[dict[str, Any]]
    stored_finding_count: NotRequired[int]
    deduplicated_findings: NotRequired[list[dict[str, Any]]]
    unique_finding_count: NotRequired[int]