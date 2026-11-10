"""Day25 HTTP integration tests for incident management."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[2]

for folder in ("day18/auth", "day21", "day22"):
    location = str(ROOT / folder)
    if location not in sys.path:
        sys.path.insert(0, location)

from day24.evidence_correlation_engine import correlate_evidence
from day25.incident_case_api import incident_case_bp
from day25.incident_case_store import (
    initialize_database,
    initialize_evidence_table,
    get_incident,
    get_incident_audit,
    get_incident_evidence,
)


class IncidentManagementAPITests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "cases.db"
        self.log = ROOT / "day21/data/simulated_security_events.log"

        initialize_database(self.db)
        initialize_evidence_table(self.db)

        self.event = correlate_evidence(self.log)["timeline"][0]
        self.alert_id = self.event["alert_id"]

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="day25-management-tests",
            DAY25_INCIDENT_DB=str(self.db),
            DAY25_ALERT_LOG=str(self.log),
        )
        self.app.register_blueprint(incident_case_bp)
        self.client = self.app.test_client()

        self.analyst = {
            "username": "test_analyst",
            "role": "ANALYST",
        }

        self.auth_patch = patch(
            "flask_session_auth.current_analyst",
            return_value=self.analyst,
        )
        self.role_patch = patch(
            "day25.incident_case_api.current_analyst",
            return_value=self.analyst,
        )

        self.auth_patch.start()
        self.role_patch.start()

        with self.client.session_transaction() as session:
            session["analyst_username"] = "test_analyst"
            session["csrf_token"] = "test-csrf-token"

        self.headers = {"X-CSRF-Token": "test-csrf-token"}

        response = self.client.post(
            "/api/day25/incidents",
            json={
                "alert_id": self.alert_id,
                "description": "Synthetic incident under investigation",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 201)
        self.case_id = response.json["incident"]["case_id"]
        self.url = f"/api/day25/incidents/{self.case_id}"

    def tearDown(self):
        self.role_patch.stop()
        self.auth_patch.stop()
        self.temp.cleanup()

    def post(self, suffix, payload, headers=None):
        return self.client.post(
            self.url + suffix,
            json=payload,
            headers=self.headers if headers is None else headers,
        )

    def test_01_status_transition(self):
        response = self.post(
            "/status",
            {"status": "INVESTIGATING", "note": "Review started"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["incident"]["status"],
            "INVESTIGATING",
        )

    def test_02_invalid_transition(self):
        response = self.post(
            "/status",
            {"status": "CLOSED", "note": "Invalid transition"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            get_incident(self.case_id, self.db)["status"],
            "OPEN",
        )

    def test_03_verdict(self):
        response = self.post(
            "/verdict",
            {
                "verdict": "TRUE_POSITIVE",
                "note": "Synthetic evidence reviewed",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["incident"]["verdict"],
            "TRUE_POSITIVE",
        )

    def test_04_valid_evidence(self):
        response = self.post(
            "/evidence",
            {
                "evidence_type": "IOC_ALERT",
                "source": "DAY22",
                "reference_id": self.alert_id,
                "description": "Verified synthetic alert",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            len(get_incident_evidence(self.case_id, self.db)),
            1,
        )

    def test_05_invalid_evidence_no_mutation(self):
        before = len(get_incident_audit(self.case_id, self.db))
        response = self.post(
            "/evidence",
            {
                "evidence_type": "LOG_EVENT",
                "source": "DAY24",
                "reference_id": "EVT-INVENTED",
                "description": "Invalid evidence",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            len(get_incident_evidence(self.case_id, self.db)),
            0,
        )
        self.assertEqual(
            len(get_incident_audit(self.case_id, self.db)),
            before,
        )

    def test_06_evidence_listing(self):
        response = self.client.get(self.url + "/evidence")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 0)

    def test_07_audit_listing(self):
        response = self.client.get(self.url + "/audit")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)

    def test_08_csrf_required(self):
        response = self.post(
            "/status",
            {"status": "INVESTIGATING", "note": "No CSRF"},
            headers={},
        )
        self.assertEqual(response.status_code, 403)

    def test_09_unauthenticated(self):
        with patch(
            "flask_session_auth.current_analyst",
            return_value=None,
        ):
            response = self.client.get(self.url + "/audit")
        self.assertEqual(response.status_code, 401)

    def test_10_non_analyst(self):
        with patch(
            "day25.incident_case_api.current_analyst",
            return_value={
                "username": "viewer",
                "role": "VIEWER",
            },
        ):
            response = self.post(
                "/status",
                {"status": "INVESTIGATING", "note": "Viewer attempt"},
            )
        self.assertEqual(response.status_code, 403)

    def test_11_missing_note(self):
        response = self.post(
            "/status",
            {"status": "INVESTIGATING"},
        )
        self.assertEqual(response.status_code, 400)

    def test_12_duplicate_evidence(self):
        payload = {
            "evidence_type": "IOC_ALERT",
            "source": "DAY22",
            "reference_id": self.alert_id,
            "description": "Synthetic IOC",
        }
        first = self.post("/evidence", payload)
        second = self.post("/evidence", payload)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(
            len(get_incident_evidence(self.case_id, self.db)),
            1,
        )

    def test_13_full_incident_lifecycle(self):
        self.assertEqual(
            self.post(
                "/status",
                {"status": "INVESTIGATING", "note": "Started"},
            ).status_code,
            200,
        )

        self.assertEqual(
            self.post(
                "/verdict",
                {
                    "verdict": "TRUE_POSITIVE",
                    "note": "Evidence analyzed",
                },
            ).status_code,
            200,
        )

        self.assertEqual(
            self.post(
                "/status",
                {"status": "RESOLVED", "note": "Review completed"},
            ).status_code,
            200,
        )

        no_evidence = self.post(
            "/status",
            {"status": "CLOSED", "note": "Premature closure"},
        )
        self.assertEqual(no_evidence.status_code, 400)

        self.assertEqual(
            self.post(
                "/evidence",
                {
                    "evidence_type": "IOC_ALERT",
                    "source": "DAY22",
                    "reference_id": self.alert_id,
                    "description": "Validated IOC",
                },
            ).status_code,
            201,
        )

        closed = self.post(
            "/status",
            {"status": "CLOSED", "note": "Evidence confirmed"},
        )
        self.assertEqual(closed.status_code, 200)
        self.assertEqual(
            closed.json["incident"]["status"],
            "CLOSED",
        )

        blocked = self.post(
            "/verdict",
            {
                "verdict": "FALSE_POSITIVE",
                "note": "Forbidden after closure",
            },
        )
        self.assertEqual(blocked.status_code, 400)


if __name__ == "__main__":
    unittest.main()
