
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[2]
DAY06_DIR = PROJECT_DIR / "day06"
DAY13_DIR = PROJECT_DIR / "day13"

sys.path.insert(0, str(DAY06_DIR))
sys.path.insert(0, str(DAY13_DIR))

from app import app
from alert_auth import load_alert_token
import alert_lifecycle_manager as manager


TEST_ID = "DAY13_API_TEST_001"


def main():
    with tempfile.TemporaryDirectory() as tmp:
        test_dir = Path(tmp)
        test_registry = test_dir / "alert_management.json"
        test_audit = test_dir / "alert_actions.jsonl"

        record = {
            "alert_id": TEST_ID,
            "severity": "CRITICAL",
            "type": "DAY13_TEST",
            "status": "NEW",
            "acknowledged_at_utc": None,
            "resolved_at_utc": None,
            "resolution_note": None
        }

        test_registry.write_text(
            json.dumps([record]),
            encoding="utf-8"
        )

        with (
            patch.object(manager, "REGISTRY", test_registry),
            patch.object(manager, "AUDIT_LOG", test_audit)
        ):
            client = app.test_client()

            headers = {
                "X-Alert-Token": load_alert_token()
            }

            ack = client.post(
                "/api/alert-management/acknowledge",
                json={"alert_id": TEST_ID},
                headers=headers
            )

            print("=== ACKNOWLEDGE TEST ===")
            print("HTTP:", ack.status_code)
            print(
                "Status:",
                (ack.get_json() or {}).get(
                    "alert", {}
                ).get("status")
            )

            resolve = client.post(
                "/api/alert-management/resolve",
                json={
                    "alert_id": TEST_ID,
                    "note": "DAY13 isolated API test completed"
                },
                headers=headers
            )

            print("=== RESOLVE TEST ===")
            print("HTTP:", resolve.status_code)
            print(
                "Status:",
                (resolve.get_json() or {}).get(
                    "alert", {}
                ).get("status")
            )

            records = json.loads(
                test_registry.read_text(encoding="utf-8")
            )

            audit = test_audit.read_text(
                encoding="utf-8"
            ).splitlines()

            passed = (
                ack.status_code == 200
                and resolve.status_code == 200
                and records[0]["status"] == "RESOLVED"
                and len(audit) == 2
            )

            print("=== FINAL VERIFICATION ===")
            print("Final status:", records[0]["status"])
            print("Audit entries:", len(audit))
            print("Test passed:", passed)

            if not passed:
                raise SystemExit(1)


if __name__ == "__main__":
    main()
