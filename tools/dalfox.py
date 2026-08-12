import subprocess


def run_dalfox(
    target_url: str,
    cookie: str | None = None,
    timeout: int = 300,
) -> str:
    """Run Dalfox in a Docker container against a target URL."""

    command = [
        "docker",
        "run",
        "--rm",
        "hahwul/dalfox:latest",
        "./dalfox",
        "url",
        "--url",
        target_url,
    ]

    if cookie:
        command.extend([
            "--cookies",
            cookie,
        ])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    return result.stdout + result.stderr