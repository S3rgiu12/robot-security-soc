"""Day 27 - SOC integrity API authorization tests."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "day18/auth")
)

from day27.incident_integrity_api import integrity_bp


CASE_ID = "INC-CAC40C42F3254074"

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "exports"
    / CASE_ID
)

ANALYST = {
    "username": "test_analyst",
    "role": "ANALYST",
}

VIEWER = {
    "username": "test_viewer",
    "role": "VIEWER",
}


class TestIncidentIntegrityAPI(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name) / "exports"
        self.root.mkdir()

        self.bundle = self.root / CASE_ID
        shutil.copytree(SOURCE, self.bundle)

        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.secret_key = "day27-test-only"
        self.app.register_blueprint(integrity_bp)

        self.client = self.app.test_client()

        self.url = (
            f"/api/day27/incidents/{CASE_ID}/integrity"
        )

        self.root_patch = patch(
            "day27.incident_integrity_api.verify_secure_bundle",
            side_effect=self.verify_test_bundle,
        )
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def verify_test_bundle(self, case_id):
        from day27.secure_bundle_verifier import (
            verify_secure_bundle,
        )
        return verify_secure_bundle(case_id, self.root)

    def request_as(self, user, url=None):
        with patch(
            "flask_session_auth.current_analyst",
            return_value=user,
        ), patch(
            "day27.incident_integrity_api.current_analyst",
            return_value=user,
        ):
            return self.client.get(url or self.url)

    def test_unauthenticated_401(self):
        response = self.request_as(None)
        self.assertEqual(response.status_code, 401)

    def test_viewer_403(self):
        response = self.request_as(VIEWER)
        self.assertEqual(response.status_code, 403)

    def test_analyst_valid_200(self):
        response = self.request_as(ANALYST)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["status"], "VALID"
        )
        self.assertEqual(
            response.json["verified_count"], 3
        )
        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )

    def test_invalid_case_id_400(self):
        url = (
            "/api/day27/incidents/"
            "INVALID-CASE/integrity"
        )
        response = self.request_as(ANALYST, url)

        self.assertEqual(response.status_code, 400)

    def test_invalid_manifest_404(self):
        manifest = self.bundle / "manifest.json"
        manifest.write_text(
            "not valid json",
            encoding="utf-8",
        )

        response = self.request_as(ANALYST)

        self.assertEqual(response.status_code, 404)

    def test_tampered_report_200(self):
        report = self.bundle / "incident-report.json"

        with report.open("ab") as stream:
            stream.write(b"\nMODIFIED")

        response = self.request_as(ANALYST)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["status"], "TAMPERED"
        )
        self.assertFalse(
            response.json["files"]["incident-report.json"]
        )


if __name__ == "__main__":
    unittest.main()
