
import hmac
import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent / ".env.day13"


def load_alert_token():
    if not ENV_FILE.is_file():
        raise RuntimeError("Missing .env.day13")

    settings = {}

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, separator, value = line.partition("=")

        if separator:
            settings[key.strip()] = value.strip()

    token = settings.get("ALERT_MANAGEMENT_TOKEN", "")

    if len(token) < 32:
        raise RuntimeError("Invalid alert management token")

    return token


def verify_alert_token(provided_token):
    expected_token = load_alert_token()

    return hmac.compare_digest(
        provided_token or "",
        expected_token
    )
