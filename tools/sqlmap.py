import subprocess


def run_sqlmap(
    target_url: str,
    cookie: str,
    timeout: int = 300,
) -> str:
    """Run SQLMap in a Docker container against a target URL."""

    command = [
        "docker",
        "run",
        "--rm",
        "parrotsec/sqlmap",
        "-u",
        target_url,
        f"--cookie={cookie}",
        "--batch",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    return result.stdout + result.stderr


if __name__ == "__main__":
    print("SQLMap tool wrapper ready.")