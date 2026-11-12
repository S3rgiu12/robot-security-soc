"""Validate IDS V3 alerts before SOC evidence attachment."""

import hashlib
from pathlib import Path


ALERT_MARKER = "Multiple TLS certificate rejections detected!"


def create_ids_alert_id(alert_line):
    """Create a deterministic identifier for an IDS alert."""

    digest = hashlib.sha256(
        alert_line.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"IDS-{digest}"


def validate_ids_alert(
    reference_id,
    incident_alert_id,
    log_path,
):
    """Verify that an IDS alert exists in the selected alert log."""

    if (
        not isinstance(reference_id, str)
        or not reference_id.strip()
    ):
        raise ValueError("IDS alert reference is required")

    if reference_id != incident_alert_id:
        raise ValueError(
            "IDS alert does not match incident"
        )

    path = Path(log_path)

    if not path.is_file():
        raise ValueError("IDS alert log not found")

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line in file:
            alert_line = line.rstrip("\r\n")

            if " | CRITICAL | " not in alert_line:
                continue

            if ALERT_MARKER not in alert_line:
                continue

            if create_ids_alert_id(alert_line) == reference_id:
                return True

    raise ValueError(
        "IDS alert reference not found in selected log"
    )
