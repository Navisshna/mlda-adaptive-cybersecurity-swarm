"""LaTeX rendering for cybersecurity assessment reports."""

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from mlda_swarm.logging_utils import log_event
from mlda_swarm.reporting.redaction import redact_text


TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report_template.tex"


def load_report_json(
    json_path: str | Path,
) -> dict[str, Any]:
    """Load a sanitized JSON report."""

    json_path = Path(json_path)

    with json_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def escape_latex(value: Any) -> str:
    """Escape characters with special meaning in LaTeX."""

    if value is None:
        return ""

    text = str(value)

    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }

    return "".join(
        replacements.get(char, char)
        for char in text
    )


def render_latex_report(
    report_data: dict[str, Any],
) -> str:
    """Render sanitized report data into LaTeX."""

    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=False,
    )

    environment.filters["latex"] = escape_latex

    template = environment.get_template(
        TEMPLATE_NAME
    )

    latex = template.render(
        report=report_data
    )

    # Final defence-in-depth safety check
    safe_latex, _ = redact_text(latex)

    return safe_latex


def save_latex_report(
    report_data: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Render and save a LaTeX report."""

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    latex = render_latex_report(
        report_data
    )

    output_path.write_text(
        latex,
        encoding="utf-8",
    )

    log_event(
        run_id=report_data.get("run_id", "unknown"),
        agent_name="reporting",
        event_type="latex_report_saved",
        decision=f"LaTeX report saved to {output_path.name}.",
    )

    return output_path


def render_latex_from_json(
    json_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Convert a sanitized JSON report into a LaTeX file."""

    report_data = load_report_json(
        json_path
    )

    return save_latex_report(
        report_data,
        output_path,
    )