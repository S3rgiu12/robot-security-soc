"""Day 25 - Incident Case API security tests."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parents[2]

for folder in ("day18/auth", "day22"):
    path = str(ROOT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)

from day25.incident_case_store import (
    initialize_database,
    get_incident,
)

from day25.incident_case_api import incident_case_bp


ALERT_ID = "ALT-D12105D2C7303721"

TEST_ALERT = {
    "alert_id": ALERT_ID,
    "severity": "HIGH",
}


class IncidentCaseAPITests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "incidents.db"

        initialize_database(self.db)

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="day25-test-only",
            DAY25_INCIDENT_DB=str(self.db),
        )

        self.app.register_blueprint(incident_case_bp)

        self.client = self.app.test_client()

        # Patch only the API module's identity lookup.
        self.identity_patch = patch(
            "day25.incident_case_api.current_analyst",
            return_value={
                "username": "test_analyst",
                "role": "ANALYST",
            },
        )

        self.identity_patch.start()

        self.alert_patch = patch(
            "day25.incident_case_api.generate_alerts",
            return_value={"alerts": [TEST_ALERT]},
        )

        self.alert_patch.start()

        # The real decorator is retained and uses
        # its own current_analyst reference.
        self.auth_patch = patch(
            "flask_session_auth.current_analyst",
            return_value={
                "username": "test_analyst",
                "role": "ANALYST",
            },
        )

        self.auth_patch.start()

        with self.client.session_transaction() as session:
            session["analyst_username"] = "test_analyst"
            session["csrf_token"] = "day25-test-csrf"

    def tearDown(self):
        self.auth_patch.stop()
        self.alert_patch.stop()
        self.identity_patch.stop()
        self.temp.cleanup()

    def create_case(self, csrf=True):
        headers = {}

        if csrf:
            headers["X-CSRF-Token"] = "day25-test-csrf"

        return self.client.post(
            "/api/day25/incidents",
            json={
                "alert_id": ALERT_ID,
                "description": "Synthetic SOC incident",
            },
            headers=headers,
        )

    def test_01_list_empty(self):
        response = self.client.get(
            "/api/day25/incidents"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 0)

    def test_02_create_case(self):
        response = self.create_case()

        self.assertEqual(response.status_code, 201)

        case = response.json["incident"]

        self.assertEqual(case["status"], "OPEN")
        self.assertEqual(
            case["verdict"], "UNDETERMINED"
        )

        saved = get_incident(
            case["case_id"], self.db
        )

        self.assertIsNotNone(saved)

    def test_03_missing_csrf(self):
        response = self.create_case(csrf=False)

        self.assertEqual(response.status_code, 403)

    def test_04_unknown_alert(self):
        response = self.client.post(
            "/api/day25/incidents",
            json={
                "alert_id": "ALT-UNKNOWN",
                "description": "Unknown alert",
            },
            headers={
                "X-CSRF-Token": "day25-test-csrf"
            },
        )

        self.assertEqual(response.status_code, 404)

    def test_05_invalid_description(self):
        response = self.client.post(
            "/api/day25/incidents",
            json={
                "alert_id": ALERT_ID,
                "description": "",
            },
            headers={
                "X-CSRF-Token": "day25-test-csrf"
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_06_details_not_found(self):
        response = self.client.get(
            "/api/day25/incidents/INC-UNKNOWN"
        )

        self.assertEqual(response.status_code, 404)

    def test_07_non_analyst_role(self):
        with patch(
            "day25.incident_case_api.current_analyst",
            return_value={
                "username": "viewer",
                "role": "VIEWER",
            },
        ):
            response = self.client.get(
                "/api/day25/incidents"
            )

        self.assertEqual(response.status_code, 403)

    def test_08_unauthenticated(self):
        with patch(
            "flask_session_auth.current_analyst",
            return_value=None,
        ):
            response = self.client.get(
                "/api/day25/incidents"
            )

        self.assertEqual(response.status_code, 401)

    def test_09_invalid_json(self):
        response = self.client.post(
            "/api/day25/incidents",
            data="not-json",
            content_type="text/plain",
            headers={
                "X-CSRF-Token": "day25-test-csrf"
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_10_list_after_creation(self):
        self.create_case()

        response = self.client.get(
            "/api/day25/incidents"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)


if __name__ == "__main__":
    unittest.main()
