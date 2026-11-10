from flask import Blueprint, jsonify, current_app

from flask_session_auth import (
    require_analyst,
    current_analyst
)

from threat_alert_engine import generate_alerts


threat_alert_bp = Blueprint(
    "threat_alert",
    __name__
)


@threat_alert_bp.route(
    "/api/day22/threat-alerts",
    methods=["GET"]
)
@require_analyst
def get_threat_alerts():

    user = current_analyst()

    if user is None or user.get("role") != "ANALYST":
        return jsonify({
            "error": "Analyst role required"
        }), 403

    try:
        results = generate_alerts()

    except (OSError, ValueError, KeyError, TypeError) as exc:
        current_app.logger.error(
            "Threat alert generation failed: %s",
            type(exc).__name__
        )

        return jsonify({
            "status": "ERROR",
            "error": "Threat alert generation unavailable"
        }), 503

    return jsonify(results), 200
