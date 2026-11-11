
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
    def test_csp_enforcement(self):
        response = self.client.get("/soc-login")

        csp = response.headers.get(
            "Content-Security-Policy"
        )

        self.assertIsNotNone(csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_login_uses_external_assets(self):
        response = self.client.get("/soc-login")
        html = response.get_data(as_text=True)

        self.assertIn("/static/css/soc-login.css", html)
        self.assertIn("/static/js/soc-login.js", html)
        self.assertNotIn("<style>", html)
        self.assertNotIn("<script>", html)

    def test_login_static_assets(self):
        assets = [
            "/static/css/soc-login.css",
            "/static/js/soc-login.js",
        ]

        for asset in assets:
            with self.subTest(asset=asset):
                with self.client.get(asset) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertGreater(len(response.get_data()), 0)

if __name__ == "__main__":
    unittest.main()
