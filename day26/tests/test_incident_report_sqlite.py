import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from day25.incident_case_store import (
    initialize_database,
    initialize_evidence_table,
    create_incident,
)
from day26.incident_report_engine import (
    generate_incident_report,
    report_to_json,
)


class TestIncidentReportSQLite(unittest.TestCase):

    def test_real_sqlite_report_is_read_only(self):
        with tempfile.TemporaryDirectory(
            prefix="day26_soc_test_"
        ) as temp_dir:

            db_path = Path(temp_dir) / "incidents.db"

            initialize_database(db_path)
            initialize_evidence_table(db_path)

            incident = create_incident(
                alert_id="ALERT-TEST-001",
                severity="HIGH",
                analyst="test_analyst",
                description="Synthetic SOC incident for Day26",
                db_path=db_path,
            )

            case_id = incident["case_id"]

            def snapshot():
                with sqlite3.connect(db_path) as conn:
                    return {
                        "incident": conn.execute(
                            "SELECT * FROM incident_cases "
                            "ORDER BY case_id"
                        ).fetchall(),
                        "evidence": conn.execute(
                            "SELECT * FROM incident_evidence "
                            "ORDER BY id"
                        ).fetchall(),
                        "audit": conn.execute(
                            "SELECT * FROM incident_case_audit "
                            "ORDER BY id"
                        ).fetchall(),
                        "total_changes": conn.total_changes,
                    }

            before = snapshot()

            report = generate_incident_report(
                case_id,
                db_path,
            )

            after = snapshot()

            self.assertEqual(before, after)

            self.assertEqual(
                report["report_type"],
                "SOC_INCIDENT_REPORT",
            )

            self.assertEqual(
                report["incident"]["case_id"],
                case_id,
            )

            self.assertEqual(
                report["incident"]["status"],
                "OPEN",
            )

            self.assertEqual(
                report["incident"]["severity"],
                "HIGH",
            )

            self.assertEqual(
                report["incident"]["verdict"],
                "UNDETERMINED",
            )

            self.assertEqual(
                report["summary"]["evidence_count"],
                0,
            )

            self.assertEqual(
                report["summary"]["audit_events"],
                1,
            )

            self.assertEqual(
                report["audit_trail"][0]["action"],
                "CASE_CREATED",
            )

            output = report_to_json(report)
            decoded = json.loads(output)

            self.assertEqual(
                decoded["incident"]["case_id"],
                case_id,
            )

            with sqlite3.connect(db_path) as conn:
                integrity = conn.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0]

            self.assertEqual(integrity, "ok")

            print()
            print("=== DAY26 SQLITE INTEGRATION ===")
            print("Incident:", case_id)
            print("Status:", report["incident"]["status"])
            print("Evidence:", report["summary"]["evidence_count"])
            print("Audit events:", report["summary"]["audit_events"])
            print("Database unchanged:", before == after)
            print("SQLite integrity:", integrity)
            print("DAY26 SQLITE INTEGRATION: PASS")


if __name__ == "__main__":
    unittest.main()
