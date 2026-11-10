"""Day26 - Authenticated HTTP reporting tests."""

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[2]
AUTH_DIR = ROOT / "day18" / "auth"

if str(AUTH_DIR) not in sys.path:
    sys.path.insert(0, str(AUTH_DIR))

from day25.incident_case_store import (
    initialize_database,
    initialize_evidence_table,
    create_incident,
)
from day26.incident_report_api import incident_report_bp


class TestIncidentReportHTTP(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = (
            Path(self.temp_dir.name) / "incidents.db"
        )

        initialize_database(self.db_path)
        initialize_evidence_table(self.db_path)

        incident = create_incident(
            alert_id="ALERT-DAY26-HTTP-TEST",
            severity="HIGH",
            analyst="test_analyst",
            description="Synthetic HTTP reporting test",
            db_path=self.db_path,
        )

        self.case_id = incident["case_id"]

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="day26-http-test-only",
            DAY25_INCIDENT_DB=self.db_path,
        )

        self.app.register_blueprint(incident_report_bp)
        self.client = self.app.test_client()

        # Patch the identity lookup used by the decorator.
        self.identity_patch = patch(
            "flask_session_auth.current_analyst",
            return_value={
                "username": "test_analyst",
                "role": "ANALYST",
            },
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

        self.reporting_identity_patch = patch(
            "day26.incident_report_api.current_analyst",
            return_value={
                "username": "test_analyst",
                "role": "ANALYST",
            },
        )
        self.reporting_identity_patch.start()
        self.addCleanup(self.reporting_identity_patch.stop)


    def url(self, suffix):
        return (
            f"/api/day26/incidents/"
            f"{self.case_id}/{suffix}"
        )

    def test_authenticated_json_report(self):
        response = self.client.get(self.url("report"))

        self.assertEqual(response.status_code, 200)

        report = response.get_json()

        self.assertEqual(
            report["report_type"],
            "SOC_INCIDENT_REPORT",
        )
        self.assertEqual(
            report["incident"]["case_id"],
            self.case_id,
        )

    def test_authenticated_evidence_csv(self):
        response = self.client.get(
            self.url("evidence.csv")
        )

        self.assertEqual(response.status_code, 200)

        rows = list(
            csv.DictReader(
                io.StringIO(response.get_data(as_text=True))
            )
        )

        self.assertEqual(rows, [])

    def test_authenticated_audit_csv(self):
        response = self.client.get(
            self.url("audit.csv")
        )

        self.assertEqual(response.status_code, 200)

        rows = list(
            csv.DictReader(
                io.StringIO(response.get_data(as_text=True))
            )
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["action"],
            "CASE_CREATED",
        )

    def test_invalid_case_id_http_400(self):
        response = self.client.get(
            "/api/day26/incidents/INVALID-ID/report"
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_case_http_404(self):
        response = self.client.get(
            "/api/day26/incidents/INC-NOTFOUND/report"
        )

        self.assertEqual(response.status_code, 404)

    def test_sensitive_responses_not_cached(self):
        for suffix in (
            "report",
            "evidence.csv",
            "audit.csv",
        ):
            with self.subTest(suffix=suffix):
                response = self.client.get(
                    self.url(suffix)
                )

                self.assertEqual(
                    response.headers.get("Cache-Control"),
                    "no-store",
                )

                self.assertEqual(
                    response.headers.get(
                        "X-Content-Type-Options"
                    ),
                    "nosniff",
                )


if __name__ == "__main__":
    unittest.main()
