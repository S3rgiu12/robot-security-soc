import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "day06"))
sys.path.insert(0, str(ROOT / "day18" / "auth"))

from app import app
import analyst_auth
import flask_session_auth
import soc_auth_api


class TestSOCFlaskIntegration(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "users.db"

        analyst_auth.initialize_auth(self.db)
        analyst_auth.create_analyst(
            "soc_test_01",
            "TemporaryTestPassword_2026!",
            db_path=self.db
        )

        self.patches = [
            patch.object(
                flask_session_auth,
                "authenticate_analyst",
                lambda u, p: analyst_auth.authenticate_analyst(
                    u, p, self.db
                )
            ),
            patch.object(
                flask_session_auth,
                "connect_auth",
                lambda: analyst_auth.connect_auth(self.db)
            )
        ]

        for item in self.patches:
            item.start()

        soc_auth_api.failed_attempts.clear()

        self.client = app.test_client()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()

        soc_auth_api.failed_attempts.clear()
        self.temp.cleanup()

    def login(self):
        return self.client.post(
            "/api/soc-auth/login",
            json={
                "username": "soc_test_01",
                "password": "TemporaryTestPassword_2026!"
            }
        )

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_unauthenticated_session(self):
        response = self.client.get("/api/soc-auth/me")
        self.assertEqual(response.status_code, 401)

    def test_login(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["user"]["username"],
            "soc_test_01"
        )

    def test_authenticated_session(self):
        self.login()
        response = self.client.get("/api/soc-auth/me")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["authenticated"])

    def test_csrf_endpoint(self):
        self.login()
        response = self.client.get("/api/soc-auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["csrf_token"])

    def test_logout_requires_csrf(self):
        self.login()
        response = self.client.post("/api/soc-auth/logout")
        self.assertEqual(response.status_code, 403)

    def test_logout_invalidates_session(self):
        login = self.login()
        token = login.json["csrf_token"]

        response = self.client.post(
            "/api/soc-auth/logout",
            headers={"X-CSRF-Token": token}
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/soc-auth/me")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
