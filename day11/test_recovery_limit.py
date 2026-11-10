
import json
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import ids_recovery_controller as controller


def main():
    print("=== RECOVERY LIMIT TEST ===")

    now = controller.utc_now()

    # Simulăm trei încercări în ultimele 10 minute.
    attempts = [
        (now - timedelta(minutes=3)).isoformat(),
        (now - timedelta(minutes=2)).isoformat(),
        (now - timedelta(minutes=1)).isoformat()
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        test_state = Path(temp_dir) / "recovery_state.json"

        test_state.write_text(
            json.dumps({"attempts": attempts}),
            encoding="utf-8"
        )

        # Redirecționăm numai istoricul către fișierul de test.
        with patch.object(controller, "STATE_FILE", test_state):
            loaded = controller.load_attempts()

            print("Maximum attempts:", controller.MAX_ATTEMPTS)
            print("Window minutes:", controller.WINDOW_MINUTES)
            print("Recent attempts:", len(loaded))

            # Simulăm starea în care IDS-ul este oprit.
            fake_status = {
                "state": "OFFLINE",
                "process_running": False
            }

            with patch.object(
                controller, "monitor_ids",
                return_value=fake_status
            ):
                with patch.object(
                    controller,
                    "IDS_SCRIPT",
                    Path(__file__)
                ):
                    # Nu trebuie să ajungem la pornirea unui proces.
                    with patch.object(
                        controller.subprocess,
                        "Popen",
                        side_effect=AssertionError(
                            "Unexpected process start!"
                        )
                    ) as start_mock:
                        result = controller._recover_ids_unlocked()

                        assert result is False
                        assert not start_mock.called

            print("Recovery blocked:", not result)
            print("New process started:", start_mock.called)

            if not result and not start_mock.called:
                print("[OK] Restart limit enforced.")
            else:
                print("[FAILED] Restart limit not enforced.")


if __name__ == "__main__":
    main()
