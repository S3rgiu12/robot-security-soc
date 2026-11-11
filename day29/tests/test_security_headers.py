
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "day06"))

from app import app


class TestSecurityHeaders(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def check_headers(self, response):
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"),
            "nosniff"
        )
        self.assertEqual(
            response.headers.get("X-Frame-Options"),
            "DENY"
        )
        self.assertEqual(
            response.headers.get("Referrer-Policy"),
            "strict-origin-when-cross-origin"
        )

    def test_login_security_headers(self):
        response = self.client.get("/soc-login")

        self.assertEqual(response.status_code, 200)
        self.check_headers(response)

    def test_dashboard_redirect_security_headers(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get("Location"),
            "/soc-login"
        )
        self.check_headers(response)


if __name__ == "__main__":
    unittest.main()
