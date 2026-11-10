import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from flask import Flask, session

ROOT = Path(__file__).resolve().parents[2]

for folder in ("day18/auth", "day22", "day23"):
    path = str(ROOT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)

import investigation_api
import flask_session_auth

from investigation_api import investigation_bp
from threat_alert_engine import generate_alerts


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)


def main():
    synthetic = generate_alerts(
        log_path=str(
            ROOT / "day21/data/simulated_security_events.log"
        )
    )

    alerts = synthetic["alerts"]
    assert len(alerts) == 3

    alert_id = alerts[0]["alert_id"]

    with tempfile.TemporaryDirectory() as directory:
        app = Flask("day23_security_test")
        app.config.update(
            TESTING=True,
            SECRET_KEY="day23-isolated-test-secret",
            DAY23_INVESTIGATION_DB=str(
                Path(directory) / "investigations.db"
            ),
        )

        app.register_blueprint(investigation_bp)

        client = app.test_client()

        def mock_analyst():
            if session.get("analyst_username") == "TEST_ANALYST":
                return {
                    "username": "TEST_ANALYST",
                    "role": "ANALYST",
                }
            return None

        with (
            patch.object(
                investigation_api,
                "generate_alerts",
                return_value=synthetic,
            ),
            patch.object(
                flask_session_auth,
                "current_analyst",
                side_effect=mock_analyst,
            ),
            patch.object(
                investigation_api,
                "current_analyst",
                side_effect=mock_analyst,
            ),
        ):
            base = "/api/day23/investigations"
            target = f"{base}/{alert_id}"

            response = client.get(base)

            check(
                response.status_code == 401,
                "Unauthenticated GET rejected (401)",
            )

            response = client.post(
                f"{target}/status",
                json={"status": "INVESTIGATING"},
            )

            check(
                response.status_code == 401,
                "Unauthenticated POST rejected (401)",
            )

            with client.session_transaction() as sess:
                sess["analyst_username"] = "TEST_ANALYST"
                sess["csrf_token"] = "isolated-test-csrf"

            response = client.get(base)

            check(
                response.status_code == 200
                and response.json["total"] == 3,
                "Authenticated alert listing",
            )

            response = client.get(target)

            check(
                response.status_code == 200
                and response.json["investigation"]["status"]
                == "UNREVIEWED",
                "Initial investigation status",
            )

            response = client.post(
                f"{target}/status",
                json={"status": "INVESTIGATING"},
            )

            check(
                response.status_code == 403,
                "Missing CSRF rejected (403)",
            )

            headers = {
                "X-CSRF-Token": "isolated-test-csrf"
            }

            response = client.post(
                f"{target}/status",
                headers=headers,
                json={
                    "status": "INVESTIGATING",
                    "note": "Starting synthetic investigation",
                },
            )

            check(
                response.status_code == 200
                and response.json["investigation"]["status"]
                == "INVESTIGATING",
                "Authorized investigation started",
            )

            response = client.post(
                f"{target}/notes",
                headers=headers,
                json={
                    "note": "Reviewed synthetic IOC evidence"
                },
            )

            check(
                response.status_code == 200,
                "Investigation note added",
            )

            response = client.post(
                f"{target}/status",
                headers=headers,
                json={
                    "status": "CONFIRMED",
                    "note": "Synthetic evidence confirmed",
                },
            )

            check(
                response.status_code == 200
                and response.json["investigation"]["status"]
                == "CONFIRMED",
                "Investigation confirmed",
            )

            response = client.get(f"{target}/audit")

            check(
                response.status_code == 200
                and response.json["total"] == 3,
                "Three audit events recorded",
            )

            response = client.post(
                f"{target}/status",
                headers=headers,
                json={
                    "status": "INVESTIGATING",
                    "note": "Attempt to reopen",
                },
            )

            check(
                response.status_code == 400,
                "Invalid status transition rejected",
            )

            response = client.get(
                f"{base}/ALT-UNKNOWN"
            )

            check(
                response.status_code == 404,
                "Unknown alert rejected (404)",
            )

    print()
    print("DAY23 API SECURITY TESTS: ALL PASS")


if __name__ == "__main__":
    main()
