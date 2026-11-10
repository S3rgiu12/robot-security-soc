"""Day26 API authentication and validation tests."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[2]
AUTH_DIR = ROOT / "day18" / "auth"

if str(AUTH_DIR) not in sys.path:
    sys.path.insert(0, str(AUTH_DIR))

from day26.incident_report_api import incident_report_bp


class TestIncidentReportAPI(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="day26-test-only-key",
        )
        self.app.register_blueprint(incident_report_bp)
        self.client = self.app.test_client()

    def test_routes_registered(self):
        routes = {
            rule.rule
            for rule in self.app.url_map.iter_rules()
        }

        for suffix in ("report", "evidence.csv", "audit.csv"):
            self.assertIn(
                f"/api/day26/incidents/<case_id>/{suffix}",
                routes,
            )

    def test_unauthenticated_requests_denied(self):
        for suffix in ("report", "evidence.csv", "audit.csv"):
            with self.subTest(suffix=suffix):
                response = self.client.get(
                    f"/api/day26/incidents/INC-TEST-001/{suffix}"
                )
                self.assertEqual(response.status_code, 401)

    def test_invalid_case_id_rejected(self):
        with patch(
            "day26.incident_report_api.require_analyst",
        ) if False else self.app.app_context():
            pass

        # Authentication is tested independently above.
        # Route validation is tested directly through load_report.
        from day26.incident_report_api import load_report

        with self.app.app_context():
            with self.assertRaises(ValueError):
                load_report("INVALID-ID")

    def test_missing_incident_returns_404(self):
        from day26.incident_report_api import (
            IncidentReportError,
            handle_report_error,
        )

        with self.app.app_context():
            response = handle_report_error(
                IncidentReportError("Incident not found")
            )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.get_json()["error"],
            "Incident not found",
        )


if __name__ == "__main__":
    unittest.main()
