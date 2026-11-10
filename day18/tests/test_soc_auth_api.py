import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "auth"

sys.path.insert(0, str(AUTH))

import analyst_auth
import flask_session_auth
import soc_auth_api


class TestSOCAuthAPI(unittest.TestCase):

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

        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="test-only-secret",
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Strict"
        )

        self.app.register_blueprint(
            soc_auth_api.soc_auth_bp
        )

        self.client = self.app.test_client()

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

    def test_login_success(self):
        response = self.login()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["status"],
            "AUTHENTICATED"
        )

    def test_invalid_password(self):
        response = self.client.post(
            "/api/soc-auth/login",
            json={
                "username": "soc_test_01",
                "password": "incorrect-password"
            }
        )

        self.assertEqual(response.status_code, 401)

    def test_session_identity(self):
        self.login()

        response = self.client.get(
            "/api/soc-auth/me"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["user"]["username"],
            "soc_test_01"
        )

    def test_csrf_protection(self):
        self.login()

        response = self.client.post(
            "/api/soc-auth/logout"
        )

        self.assertEqual(response.status_code, 403)

    def test_logout(self):
        login_response = self.login()

        token = login_response.json["csrf_token"]

        response = self.client.post(
            "/api/soc-auth/logout",
            headers={"X-CSRF-Token": token}
        )

        self.assertEqual(response.status_code, 200)

        response = self.client.get(
            "/api/soc-auth/me"
        )

        self.assertEqual(response.status_code, 401)

    def test_rate_limiting(self):
        for _ in range(5):
            response = self.client.post(
                "/api/soc-auth/login",
                json={
                    "username": "soc_test_01",
                    "password": "wrong-password"
                }
            )

            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/api/soc-auth/login",
            json={
                "username": "soc_test_01",
                "password": "wrong-password"
            }
        )

        self.assertEqual(response.status_code, 429)


if __name__ == "__main__":
    unittest.main()
