
import logging
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "robot_security.log"

logger = logging.getLogger("RobotSecurity")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)


def log_connection(host, port):
    logger.info(
        "Robot connecting to %s:%s", host, port
    )


def log_security_alert(reason):
    logger.warning(
        "SECURITY ALERT: %s", reason
    )


def log_success(message):
    logger.info(
        "SUCCESS: %s", message
    )


if __name__ == "__main__":
    log_connection("127.0.0.1", 9443)
    log_success("Trusted TLS connection established")
    log_security_alert(
        "Untrusted TLS certificate detected"
    )

    print("=== ROBOT SECURITY LOGGER ===")
    print("Security events recorded successfully!")
    print("Log file:", LOG_FILE)
