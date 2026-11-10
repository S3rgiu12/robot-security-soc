import sys
import tempfile
import threading
import unittest
from pathlib import Path

DAY18 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DAY18))

from analyst_workflow_engine import (
    initialize,
    list_cases,
    get_audit,
    assign_case,
)


class TestConcurrentAssignment(unittest.TestCase):

    def test_two_analysts_one_incident(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "concurrency.db"

            initialize(db_path)

            barrier = threading.Barrier(2)
            results = []
            lock = threading.Lock()

            def attempt_assignment(analyst):
                try:
                    barrier.wait(timeout=5)

                    assign_case(
                        "INC-0001",
                        analyst,
                        analyst,
                        db_path
                    )

                    outcome = ("SUCCESS", analyst)

                except Exception as error:
                    outcome = (
                        "ERROR",
                        analyst,
                        type(error).__name__,
                        str(error)
                    )

                with lock:
                    results.append(outcome)

            threads = [
                threading.Thread(
                    target=attempt_assignment,
                    args=("soc_analyst_01",)
                ),
                threading.Thread(
                    target=attempt_assignment,
                    args=("soc_analyst_02",)
                ),
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join(timeout=15)

            self.assertTrue(
                all(not thread.is_alive() for thread in threads),
                "A worker thread did not finish"
            )

            successes = [
                result for result in results
                if result[0] == "SUCCESS"
            ]

            failures = [
                result for result in results
                if result[0] == "ERROR"
            ]

            self.assertEqual(
                len(successes), 1,
                f"Expected one success: {results}"
            )

            self.assertEqual(
                len(failures), 1,
                f"Expected one rejection: {results}"
            )

            case = next(
                item for item in list_cases(db_path)
                if item["incident_id"] == "INC-0001"
            )

            self.assertEqual(
                case["workflow_status"],
                "ASSIGNED"
            )

            self.assertEqual(
                case["assigned_to"],
                successes[0][1]
            )

            audit = get_audit("INC-0001", db_path)

            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["action"], "ASSIGN")

            print("\n=== CONCURRENT ASSIGNMENT RESULTS ===")
            for result in results:
                print(result)

            print("Final analyst:", case["assigned_to"])
            print("Audit records:", len(audit))


if __name__ == "__main__":
    unittest.main()
