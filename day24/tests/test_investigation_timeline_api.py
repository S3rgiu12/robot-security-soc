import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[2]

for folder in ("day18/auth", "day21", "day22", "day24"):
    location = str(ROOT / folder)
    if location not in sys.path:
        sys.path.insert(0, location)

import investigation_timeline_api as api

SYNTHETIC_LOG = (
    ROOT / "day21/data/simulated_security_events.log"
)

REAL_IDS_LOG = (
    ROOT / "day05/logs/robot_security.log"
)


class TestInvestigationTimelineAPI(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="day24-isolated-test-only",
            DAY24_TIMELINE_LOG=str(SYNTHETIC_LOG),
        )
        self.app.register_blueprint(api.timeline_bp)
        self.client = self.app.test_client()

    def get_as_analyst(self, path):
        with patch.object(
            api,
            "current_analyst",
            return_value={
                "username": "day24_test_analyst",
                "role": "ANALYST",
            }
        ), patch(
            "flask_session_auth.current_analyst",
            return_value={
                "username": "day24_test_analyst",
                "role": "ANALYST",
            }
        ):
            return self.client.get(path)

    def test_unauthenticated_list_rejected(self):
        response = self.client.get(
            "/api/day24/timeline"
        )
        self.assertEqual(response.status_code, 401)

    def test_unauthenticated_details_rejected(self):
        response = self.client.get(
            "/api/day24/timeline/ALT-UNKNOWN"
        )
        self.assertEqual(response.status_code, 401)

    def test_authenticated_synthetic_timeline(self):
        response = self.get_as_analyst(
            "/api/day24/timeline"
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["total_events"], 4)
        self.assertEqual(data["total_alerts"], 3)
        self.assertEqual(data["correlated_alerts"], 3)
        self.assertEqual(data["unmatched_alerts"], [])
        self.assertEqual(len(data["timeline"]), 3)

    def test_alert_details(self):
        response = self.get_as_analyst(
            "/api/day24/timeline/"
            "ALT-619C8DAF469BECE8"
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["total_events"], 1)
        self.assertEqual(
            data["timeline"][0]["ioc_value"],
            "robot-control-test.example"
        )

    def test_unknown_alert_rejected(self):
        response = self.get_as_analyst(
            "/api/day24/timeline/ALT-NOT-FOUND"
        )
        self.assertEqual(response.status_code, 404)

    def test_missing_log_returns_503(self):
        self.app.config["DAY24_TIMELINE_LOG"] = (
            "/nonexistent/day24-test.log"
        )

        response = self.get_as_analyst(
            "/api/day24/timeline"
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json()["error"],
            "Investigation timeline unavailable"
        )

    def test_real_log_has_no_ioc_alerts(self):
        self.app.config["DAY24_TIMELINE_LOG"] = (
            str(REAL_IDS_LOG)
        )

        response = self.get_as_analyst(
            "/api/day24/timeline"
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["total_events"], 28)
        self.assertEqual(data["total_alerts"], 0)
        self.assertEqual(data["timeline"], [])


if __name__ == "__main__":
    unittest.main()
