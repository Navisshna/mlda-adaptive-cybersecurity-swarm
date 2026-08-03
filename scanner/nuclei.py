import subprocess
from pathlib import Path


OUTPUT_DIR = Path("outputs")
OUTPUT_FILE = OUTPUT_DIR / "findings.jsonl"


def run_nuclei(target: str) -> Path:
    """
    Runs a Nuclei scan against the given target.
    Saves the results as JSONL in outputs/findings.jsonl.
    Returns the path to the output file.
    """

    OUTPUT_DIR.mkdir(exist_ok=True)

    command = [
        "nuclei",
        "-u",
        target,
        "-j",
        "-o",
        str(OUTPUT_FILE),
    ]

    print(f"Running Nuclei scan on {target}...")

    subprocess.run(command, check=True)

    print("Scan complete!")

    return OUTPUT_FILE