"""Export the shared Finding model as JSON Schema."""

import json
from pathlib import Path

from mlda_swarm.models.finding import Finding


def main() -> None:
    """Write the Finding JSON Schema to the documentation folder."""

    output_path = Path("docs/schemas/finding.schema.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    schema = Finding.model_json_schema()

    output_path.write_text(
        json.dumps(schema, indent=2),
        encoding="utf-8",
    )

    print(f"Finding schema written to: {output_path}")


if __name__ == "__main__":
    main()