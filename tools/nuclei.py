"""
Wrapper around the Nuclei CLI.

Executes a scan against a target and returns the raw JSONL
results as Python dictionaries.
"""

import json
import subprocess
from pathlib import Path


def run_nuclei(
    target_url: str,
    target_name: str,
    output_dir: Path = Path("outputs"),
) -> list[dict]:
    """Run a Nuclei scan and return the raw findings."""

    output_dir.mkdir(parents=True, exist_ok=True)

    raw_output_path = output_dir / f"{target_name}_nuclei_raw.jsonl"

    command = [
        "nuclei",
        "-u",
        target_url,
        "-jsonl",
        "-o",
        str(raw_output_path),
        "-silent",
    ]

    subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )

    if not raw_output_path.exists():
        return []

    results: list[dict] = []

    with raw_output_path.open("r") as file:

        for line in file:

            line = line.strip()

            if line:
                results.append(json.loads(line))

    return results