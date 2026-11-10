
import time
import logging
import signal
from pathlib import Path

from security_alert_engine import collect_alerts

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs/security_alert_monitor.log"

CHECK_INTERVAL = 5

running = True


def stop_monitor(signum, frame):
    global running
    running = False


signal.signal(signal.SIGINT, stop_monitor)
signal.signal(signal.SIGTERM, stop_monitor)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def main():
    print("=== SECURITY ALERT MONITOR V1 ===", flush=True)
    print(f"Checking every {CHECK_INTERVAL} seconds", flush=True)

    logging.info("Security Alert Monitor started")

    while running:
        try:
            alerts, new_alerts = collect_alerts()

            if new_alerts:
                critical = sum(
                    alert["severity"] == "CRITICAL"
                    for alert in new_alerts
                )

                message = (
                    f"NEW_ALERTS={len(new_alerts)} | "
                    f"CRITICAL={critical} | "
                    f"TOTAL={len(alerts)}"
                )

                print(message, flush=True)
                logging.info(message)

                for alert in new_alerts:
                    if alert["severity"] == "CRITICAL":
                        print(
                            f"[CRITICAL] {alert['type']} | "
                            f"{alert['message']}",
                            flush=True
                        )
                        logging.warning(
                            "CRITICAL ALERT | %s | %s",
                            alert["type"],
                            alert["message"]
                        )

        except Exception:
            logging.exception("Alert monitoring failed")
            print("[ERROR] Alert monitoring failed", flush=True)

        time.sleep(CHECK_INTERVAL)

    logging.info("Security Alert Monitor stopped")
    print("Monitor stopped", flush=True)


if __name__ == "__main__":
    main()
