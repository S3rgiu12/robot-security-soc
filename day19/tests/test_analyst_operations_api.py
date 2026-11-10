import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[2]

for directory in (
    ROOT / "day18",
    ROOT / "day18" / "auth",
    ROOT / "day19",
):
    sys.path.insert(0, str(directory))

import analyst_workflow_engine as engine
import analyst_operations_api as operations
import flask_session_auth


class TestAnalystOperationsAPI(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "workflow.db"

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="temporary-test-secret"
        )

        self.app.register_blueprint(
            operations.analyst_operations_bp
        )

        self.incident_id = "INC-9999"
        self.actor = "soc_test_01"

        self.patches = [
            patch.object(
                engine,
                "registry_ids",
                return_value={self.incident_id}
            ),
            patch.object(
                operations,
                "assign_case",
                side_effect=lambda **kwargs: engine.assign_case(
                    **kwargs,
                    db_path=self.db_path
                )
            ),
            patch.object(
                operations,
                "change_status",
                side_effect=lambda **kwargs: engine.change_status(
                    **kwargs,
                    db_path=self.db_path
                )
            ),
            patch.object(
                operations,
                "add_note",
                side_effect=lambda **kwargs: engine.add_note(
                    **kwargs,
                    db_path=self.db_path
                )
            ),
            patch.object(
                flask_session_auth,
                "current_analyst",
                return_value={
                    "username": self.actor,
                    "role": "ANALYST"
                }
            ),
            patch.object(
                operations,
                "current_analyst",
                return_value={
                    "username": self.actor,
                    "role": "ANALYST"
                }
            ),
        ]

        for item in self.patches:
            item.start()

        engine.initialize(self.db_path)
        self.client = self.app.test_client()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def post(self, operation, data=None, csrf=True):
        headers = {}

        if csrf:
            headers["X-CSRF-Token"] = "test-csrf-token"

        return self.client.post(
            f"/api/day19/cases/{self.incident_id}/{operation}",
            json={} if data is None else data,
            headers=headers
        )

    def authenticate(self):
        with self.client.session_transaction() as session:
            session["analyst_username"] = self.actor
            session["csrf_token"] = "test-csrf-token"

    def test_csrf_required(self):
        self.authenticate()
        response = self.post("assign", csrf=False)
        self.assertEqual(response.status_code, 403)

    def test_assign_case(self):
        self.authenticate()
        response = self.post("assign")
        self.assertEqual(response.status_code, 200)

        cases = engine.list_cases(self.db_path)
        self.assertEqual(
            cases[0]["workflow_status"],
            "ASSIGNED"
        )
        self.assertEqual(
            cases[0]["assigned_to"],
            self.actor
        )

    def test_duplicate_assignment_rejected(self):
        self.authenticate()
        self.assertEqual(
            self.post("assign").status_code, 200
        )
        self.assertEqual(
            self.post("assign").status_code, 400
        )

    def test_full_investigation_workflow(self):
        self.authenticate()

        self.assertEqual(
            self.post("assign").status_code, 200
        )

        self.assertEqual(
            self.post(
                "status",
                {"new_status": "IN_REVIEW"}
            ).status_code,
            200
        )

        self.assertEqual(
            self.post(
                "notes",
                {"note": "Investigated robot telemetry"}
            ).status_code,
            200
        )

        self.assertEqual(
            self.post(
                "status",
                {
                    "new_status": "CLOSED",
                    "note": "Investigation completed"
                }
            ).status_code,
            200
        )

        cases = engine.list_cases(self.db_path)
        self.assertEqual(
            cases[0]["workflow_status"],
            "CLOSED"
        )

        audit = engine.get_audit(
            self.incident_id,
            self.db_path
        )

        self.assertEqual(
            [item["action"] for item in audit],
            [
                "ASSIGN",
                "STATUS_CHANGE",
                "NOTE",
                "STATUS_CHANGE"
            ]
        )

    def test_close_requires_note(self):
        self.authenticate()

        self.post("assign")
        self.post(
            "status",
            {"new_status": "IN_REVIEW"}
        )

        response = self.post(
            "status",
            {"new_status": "CLOSED", "note": ""}
        )

        self.assertEqual(response.status_code, 400)

    def test_note_after_close_rejected(self):
        self.authenticate()

        self.post("assign")
        self.post(
            "status",
            {"new_status": "IN_REVIEW"}
        )
        self.post(
            "status",
            {
                "new_status": "CLOSED",
                "note": "Resolved"
            }
        )

        response = self.post(
            "notes",
            {"note": "Late modification"}
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
