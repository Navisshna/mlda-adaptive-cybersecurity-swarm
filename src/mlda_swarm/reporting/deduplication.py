"""Deterministic deduplication for security findings."""

import re

from mlda_swarm.models.finding import Finding


def normalise_text(value: str) -> str:
    """Normalise text for duplicate comparison."""

    value = value.lower().strip()

    # Replace punctuation and special characters with spaces.
    value = re.sub(r"[^a-z0-9]+", " ", value)

    # Remove repeated whitespace.
    return " ".join(value.split())


def normalise_component(value: str) -> str:
    """Normalise an affected component."""

    value = value.lower().strip()

    # Treat /login and /login/ as the same component.
    value = value.rstrip("/")

    return value


def finding_key(finding: Finding) -> tuple[str, str, str]:
    """Create a comparison key for one finding."""

    return (
        finding.target_id,
        normalise_text(finding.title),
        normalise_component(finding.affected_component),
    )


def deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """Return findings with exact normalised duplicates removed."""

    unique_findings: list[Finding] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for finding in findings:
        key = finding_key(finding)

        if key in seen_keys:
            continue

        seen_keys.add(key)
        unique_findings.append(finding)

    return unique_findings