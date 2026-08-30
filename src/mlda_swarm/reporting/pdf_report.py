"""PDF compilation for cybersecurity assessment reports."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from mlda_swarm.logging_utils import log_event
from mlda_swarm.reporting.redaction import redact_text





def get_tectonic_executable() -> str:
    """Find the Tectonic executable.

    Priority:
    1. TECTONIC_EXE environment variable
    2. System PATH
    """

    configured_path = os.environ.get("TECTONIC_EXE")

    if configured_path:
        tectonic_path = Path(configured_path)

        if tectonic_path.is_file():
            return str(tectonic_path)

        raise FileNotFoundError(
            f"TECTONIC_EXE points to a missing file: "
            f"{tectonic_path}"
        )

    system_path = shutil.which("tectonic")

    if system_path:
        return system_path

    raise FileNotFoundError(
        "Tectonic is not installed or configured. "
        "Install Tectonic and either add it to PATH "
        "or set the TECTONIC_EXE environment variable."
    )

def compile_latex_to_pdf(
    tex_path: str | Path,
    output_dir: str | Path | None = None,
    run_id: str = "unknown",
    timeout_seconds: int = 120,
) -> Path:
    """Compile a LaTeX file into PDF using Tectonic."""

    tex_path = Path(tex_path).resolve()

    if not tex_path.exists():
        raise FileNotFoundError(
            f"LaTeX file not found: {tex_path}"
        )

    if output_dir is None:
        output_dir = tex_path.parent
    else:
        output_dir = Path(output_dir).resolve()

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    tectonic_exe = get_tectonic_executable()

    command = [
        str(tectonic_exe),
        "-X",
        "compile",
        str(tex_path),
        "--outdir",
        str(output_dir),
    ]

    log_event(
        run_id=run_id,
        agent_name="reporting",
        event_type="pdf_compilation_started",
        decision="Started LaTeX to PDF compilation.",
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )

    except subprocess.TimeoutExpired as exc:
        log_event(
            run_id=run_id,
            agent_name="reporting",
            event_type="pdf_compilation_error",
            error="PDF compilation timed out.",
        )

        raise RuntimeError(
            "PDF compilation timed out."
        ) from exc

    if result.returncode != 0:
        compiler_message = (
            result.stderr
            or result.stdout
            or "Unknown Tectonic error."
        )

        # Do not expose sensitive values from compiler output.
        safe_message, _ = redact_text(
            compiler_message
        )

        log_event(
            run_id=run_id,
            agent_name="reporting",
            event_type="pdf_compilation_error",
            error=(
                "Tectonic compilation failed with "
                f"return code {result.returncode}."
            ),
        )

        raise RuntimeError(
            "Tectonic failed to compile the report:\n"
            f"{safe_message}"
        )

    pdf_path = output_dir / f"{tex_path.stem}.pdf"

    if not pdf_path.exists():
        raise RuntimeError(
            "Tectonic finished successfully, "
            "but no PDF was created."
        )

    log_event(
        run_id=run_id,
        agent_name="reporting",
        event_type="pdf_compilation_completed",
        decision=(
            f"PDF report generated as {pdf_path.name}."
        ),
    )

    return pdf_path