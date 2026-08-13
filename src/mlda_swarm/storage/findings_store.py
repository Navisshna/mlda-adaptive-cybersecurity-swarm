"""SQLite storage for validated security findings."""

import json
import sqlite3
from pathlib import Path

from mlda_swarm.models.finding import Finding


class FindingsStore:
    """Store and retrieve validated Finding objects using SQLite."""

    def __init__(self, database_path: str | Path = "data/findings.db") -> None:
        """Create a findings store.

        Args:
            database_path: Location of the SQLite database file.
        """
        self.database_path = Path(database_path)

    def initialise(self) -> None:
        """Create the database folder and findings table if needed."""

        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    tool_name TEXT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    affected_component TEXT NOT NULL,
                    evidence TEXT,
                    recommendation TEXT,
                    cvss_score REAL,
                    references_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )

    def add_finding(self, finding: Finding) -> None:
        """Save one validated finding.

        Args:
            finding: A validated Pydantic Finding object.
        """

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id,
                    run_id,
                    target_id,
                    agent_name,
                    tool_name,
                    title,
                    description,
                    severity,
                    affected_component,
                    evidence,
                    recommendation,
                    cvss_score,
                    references_json,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.run_id,
                    finding.target_id,
                    finding.agent_name,
                    finding.tool_name,
                    finding.title,
                    finding.description,
                    finding.severity,
                    finding.affected_component,
                    finding.evidence,
                    finding.recommendation,
                    finding.cvss_score,
                    json.dumps(finding.references),
                    finding.timestamp.isoformat(),
                ),
            )

    def add_findings(self, findings: list[Finding]) -> None:
        """Save multiple validated findings.

        Args:
            findings: Findings produced by one or more agents.
        """

        for finding in findings:
            self.add_finding(finding)

    def get_findings_by_run(self, run_id: str) -> list[Finding]:
        """Return all findings belonging to one swarm run."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM findings
                WHERE run_id = ?
                ORDER BY timestamp
                """,
                (run_id,),
            ).fetchall()

        return [self._row_to_finding(row) for row in rows]

    def get_findings_by_agent(
        self,
        run_id: str,
        agent_name: str,
    ) -> list[Finding]:
        """Return findings from one agent within a particular run."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM findings
                WHERE run_id = ? AND agent_name = ?
                ORDER BY timestamp
                """,
                (run_id, agent_name),
            ).fetchall()

        return [self._row_to_finding(row) for row in rows]

    def clear_run(self, run_id: str) -> None:
        """Delete all locally stored findings for one run."""

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM findings WHERE run_id = ?",
                (run_id,),
            )

    def _connect(self) -> sqlite3.Connection:
        """Open a configured SQLite connection."""

        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        """Convert one database row back into a Finding object."""

        return Finding(
            finding_id=row["finding_id"],
            run_id=row["run_id"],
            target_id=row["target_id"],
            agent_name=row["agent_name"],
            tool_name=row["tool_name"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            affected_component=row["affected_component"],
            evidence=row["evidence"],
            recommendation=row["recommendation"],
            cvss_score=row["cvss_score"],
            references=json.loads(row["references_json"]),
            timestamp=row["timestamp"],
        )