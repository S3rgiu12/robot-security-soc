"""HTTP integration tests for IDS V3 SOC evidence."""

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

from day25.ids_evidence_validator import create_ids_alert_id
from day25.incident_case_api import incident_case_bp
from day25.incident_case_store import (
    initialize_database,
    initialize_evidence_table,
    get_incident_evidence,
    get_incident_audit,
)


class IDSSOCAPITests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)

        self.db = root / "cases.db"
        self.alert_log = root / "ids_alerts.log"
        self.security_log = root / "tls_security.log"

        self.alert_line = (
            "2026-11-12 11:09:04.347447 | CRITICAL | "
            "Multiple TLS certificate rejections detected! "
            "Events: 3 within 60 seconds"
        )

        self.alert_id = create_ids_alert_id(
            self.alert_line
        )

        self.alert_log.write_text(
            self.alert_line + "\n",
            encoding="utf-8",
        )

        self.write_tls_events(3)

        initialize_database(self.db)
        initialize_evidence_table(self.db)

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="ids-soc-api-test",
            DAY25_INCIDENT_DB=str(self.db),
            DAY25_IDS_ALERT_LOG=str(self.alert_log),
            DAY25_TLS_SECURITY_LOG=str(self.security_log),
        )

        self.app.register_blueprint(incident_case_bp)
        self.client = self.app.test_client()

        self.analyst = {
            "username": "ids_test_analyst",
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

        self.alert_patch = patch(
            "day25.incident_case_api.generate_alerts",
            return_value={
                "alerts": [{
                    "alert_id": self.alert_id,
                    "severity": "CRITICAL",
                }]
            },
        )

        self.auth_patch.start()
        self.role_patch.start()
        self.alert_patch.start()

        with self.client.session_transaction() as session:
            session["analyst_username"] = (
                "ids_test_analyst"
            )
            session["csrf_token"] = (
                "ids-test-csrf"
            )

        self.headers = {
            "X-CSRF-Token": "ids-test-csrf"
        }

        response = self.client.post(
            "/api/day25/incidents",
            json={
                "alert_id": self.alert_id,
                "description": "IDS V3 SOC integration",
            },
            headers=self.headers,
        )

        self.assertEqual(
            response.status_code,
            201,
            response.get_json(),
        )

        self.case_id = (
            response.json["incident"]["case_id"]
        )

        self.evidence_url = (
            f"/api/day25/incidents/"
            f"{self.case_id}/evidence"
        )

    def tearDown(self):
        self.alert_patch.stop()
        self.role_patch.stop()
        self.auth_patch.stop()
        self.temp.cleanup()

    def write_tls_events(self, count):
        timestamps = [
            "2026-11-12 11:08:20,100",
            "2026-11-12 11:08:35,200",
            "2026-11-12 11:08:50,300",
        ]

        self.security_log.write_text(
            "".join(
                f"{timestamp} | WARNING | "
                "SECURITY ALERT: TLS certificate rejected: "
                "simulated failure\n"
                for timestamp in timestamps[:count]
            ),
            encoding="utf-8",
        )

    def attach_evidence(self, extra=None):
        payload = {
            "evidence_type": "IDS_ALERT",
            "source": "IDS_V3",
            "reference_id": self.alert_id,
            "description": "IDS V3 TLS correlation",
        }

        if extra:
            payload.update(extra)

        return self.client.post(
            self.evidence_url,
            json=payload,
            headers=self.headers,
        )

    def test_01_valid_ids_evidence(self):
        response = self.attach_evidence()

        self.assertEqual(
            response.status_code,
            201,
            response.get_json(),
        )

        evidence = get_incident_evidence(
            self.case_id,
            self.db,
        )

        audit = get_incident_audit(
            self.case_id,
            self.db,
        )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(len(audit), 2)

        self.assertEqual(
            evidence[0]["evidence_type"],
            "IDS_ALERT",
        )

    def test_02_insufficient_tls_events(self):
        self.write_tls_events(2)

        response = self.attach_evidence()

        self.assertEqual(
            response.status_code,
            400,
            response.get_json(),
        )

        self.assertEqual(
            len(get_incident_evidence(
                self.case_id, self.db
            )),
            0,
        )

        self.assertEqual(
            len(get_incident_audit(
                self.case_id, self.db
            )),
            1,
        )

    def test_03_client_paths_ignored(self):
        response = self.attach_evidence({
            "log_path": "/invalid/client/path",
            "security_log_path": "/invalid/tls/path",
        })

        self.assertEqual(
            response.status_code,
            201,
            response.get_json(),
        )

        self.assertEqual(
            len(get_incident_evidence(
                self.case_id, self.db
            )),
            1,
        )


if __name__ == "__main__":
    unittest.main()
