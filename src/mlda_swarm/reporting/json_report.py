"""JSON export for cybersecurity assessment reports."""

import json
from pathlib import Path

from mlda_swarm.logging_utils import log_event
from mlda_swarm.reporting.report_generator import (
    build_safe_report_data,
)
from mlda_swarm.reporting.report_models import SecurityReport

def render_json_report(
    report: SecurityReport,
) -> str:
    """Convert a SecurityReport into sanitized JSON."""

    safe_data = build_safe_report_data(report)

    return json.dumps(
        safe_data,
        indent=2,
        ensure_ascii=False,
    )

def save_json_report(
    report: SecurityReport,
    output_path: str | Path,
) -> Path:
    """Render and save a sanitized SecurityReport as JSON."""

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_content = render_json_report(report)

    output_path.write_text(
        json_content,
        encoding="utf-8",
    )

    log_event(
        run_id=report.run_id,
        agent_name="reporting",
        event_type="json_report_saved",
        decision=f"Sanitized JSON report saved to {output_path.name}.",
    )

    return output_path