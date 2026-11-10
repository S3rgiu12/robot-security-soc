import sys
import tempfile
import unittest
from pathlib import Path

DAY18 = Path(__file__).resolve().parents[1]

if str(DAY18) not in sys.path:
    sys.path.insert(0, str(DAY18))

from analyst_workflow_engine import (
    initialize,
    assign_case,
    change_status,
    add_note,
    get_audit,
    list_cases
)


class TestAnalystAuthorization(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "authorization.db"

        self.incident = "INC-0001"
        self.owner = "soc_analyst_01"
        self.other = "soc_analyst_02"

        initialize(self.db)

        assign_case(
            self.incident,
            self.owner,
            self.owner,
            self.db
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_other_analyst_cannot_change_status(self):
        with self.assertRaises(PermissionError):
            change_status(
                self.incident,
                "IN_REVIEW",
                self.other,
                db_path=self.db
            )

        case = next(
            c for c in list_cases(self.db)
            if c["incident_id"] == self.incident
        )

        self.assertEqual(
            case["workflow_status"],
            "ASSIGNED"
        )
        self.assertEqual(
            len(get_audit(self.incident, self.db)),
            1
        )

    def test_other_analyst_cannot_add_note(self):
        with self.assertRaises(PermissionError):
            add_note(
                self.incident,
                self.other,
                "Unauthorized modification",
                self.db
            )

        self.assertEqual(
            len(get_audit(self.incident, self.db)),
            1
        )

    def test_assigned_analyst_can_change_status(self):
        change_status(
            self.incident,
            "IN_REVIEW",
            self.owner,
            "Investigation started",
            self.db
        )

        audit = get_audit(self.incident, self.db)

        self.assertEqual(len(audit), 2)
        self.assertEqual(
            audit[-1]["action"],
            "STATUS_CHANGE"
        )

    def test_assigned_analyst_can_add_note(self):
        add_note(
            self.incident,
            self.owner,
            "Evidence reviewed",
            self.db
        )

        audit = get_audit(self.incident, self.db)

        self.assertEqual(len(audit), 2)
        self.assertEqual(
            audit[-1]["action"],
            "NOTE"
        )


if __name__ == "__main__":
    unittest.main()
