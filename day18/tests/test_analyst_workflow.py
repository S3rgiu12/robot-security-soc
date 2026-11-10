import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path

DAY18 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DAY18))

from analyst_workflow_engine import (
    initialize,
    list_cases,
    get_audit,
    assign_case,
    change_status,
    add_note,
)

INCIDENT = "INC-0001"
ANALYST = "soc_analyst_01"


class TestAnalystWorkflow(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = (
            Path(self.temp.name) / "workflow_test.db"
        )

        initialize(self.db_path)

    def tearDown(self):
        self.temp.cleanup()

    def get_case(self):
        return next(
            case
            for case in list_cases(self.db_path)
            if case["incident_id"] == INCIDENT
        )

    def test_initialization(self):
        cases = list_cases(self.db_path)

        self.assertEqual(len(cases), 11)
        self.assertTrue(
            all(c["workflow_status"] == "NEW" for c in cases)
        )

    def test_assign_case(self):
        assign_case(
            INCIDENT,
            ANALYST,
            ANALYST,
            self.db_path
        )

        case = self.get_case()

        self.assertEqual(
            case["workflow_status"],
            "ASSIGNED"
        )
        self.assertEqual(
            case["assigned_to"],
            ANALYST
        )

    def test_complete_workflow(self):
        assign_case(
            INCIDENT, ANALYST, ANALYST, self.db_path
        )

        change_status(
            INCIDENT, "IN_REVIEW",
            ANALYST, "Investigation started",
            self.db_path
        )

        change_status(
            INCIDENT, "CLOSED",
            ANALYST, "Analysis completed",
            self.db_path
        )

        self.assertEqual(
            self.get_case()["workflow_status"],
            "CLOSED"
        )

        self.assertEqual(
            len(get_audit(INCIDENT, self.db_path)),
            3
        )

    def test_add_note(self):
        assign_case(
            INCIDENT, ANALYST, ANALYST, self.db_path
        )

        add_note(
            INCIDENT,
            ANALYST,
            "Heartbeat timeout under investigation",
            self.db_path
        )

        audit = get_audit(INCIDENT, self.db_path)

        self.assertEqual(audit[-1]["action"], "NOTE")
        self.assertIn(
            "Heartbeat timeout",
            audit[-1]["note"]
        )

    def test_invalid_transition(self):
        with self.assertRaises(ValueError):
            change_status(
                INCIDENT,
                "CLOSED",
                ANALYST,
                db_path=self.db_path
            )

    def test_duplicate_assignment_rejected(self):
        assign_case(
            INCIDENT, ANALYST, ANALYST, self.db_path
        )

        with self.assertRaises(ValueError):
            assign_case(
                INCIDENT, "soc_analyst_02",
                ANALYST, self.db_path
            )

    def test_closed_case_rejects_notes(self):
        assign_case(
            INCIDENT, ANALYST, ANALYST, self.db_path
        )

        change_status(
            INCIDENT, "IN_REVIEW",
            ANALYST, db_path=self.db_path
        )

        change_status(
            INCIDENT, "CLOSED",
            ANALYST, db_path=self.db_path
        )

        with self.assertRaises(ValueError):
            add_note(
                INCIDENT, ANALYST,
                "Unauthorized modification",
                self.db_path
            )

    def test_invalid_actor(self):
        with self.assertRaises(ValueError):
            assign_case(
                INCIDENT,
                "../invalid",
                ANALYST,
                self.db_path
            )

    def test_invalid_incident(self):
        with self.assertRaises(ValueError):
            assign_case(
                "INC-9999",
                ANALYST,
                ANALYST,
                self.db_path
            )

    def test_audit_persistence(self):
        assign_case(
            INCIDENT, ANALYST, ANALYST, self.db_path
        )

        with sqlite3.connect(self.db_path) as db:
            count = db.execute(
                "SELECT COUNT(*) FROM analyst_audit"
            ).fetchone()[0]

        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
