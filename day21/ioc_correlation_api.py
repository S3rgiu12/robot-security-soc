from flask import Blueprint, jsonify, current_app

from flask_session_auth import (
    require_analyst,
    current_analyst
)

from ioc_correlation_engine import correlate_log


ioc_correlation_bp = Blueprint(
    "ioc_correlation",
    __name__
)


@ioc_correlation_bp.route(
    "/api/day21/ioc-correlations",
    methods=["GET"]
)
@require_analyst
def get_ioc_correlations():

    user = current_analyst()

    if user is None or user.get("role") != "ANALYST":
        return jsonify({
            "error": "Analyst role required"
        }), 403

    try:
        results = correlate_log()

    except (OSError, ValueError) as exc:
        current_app.logger.error(
            "IOC correlation failed: %s",
            type(exc).__name__
        )

        return jsonify({
            "status": "ERROR",
            "error": "IOC correlation unavailable"
        }), 503

    return jsonify({
        "status": "OK",
        "source": "LOCAL_SYNTHETIC_TEST_DATA",
        "total_lines": results["total_lines"],
        "total_indicators": results["total_indicators"],
        "total_matches": results["total_matches"],
        "matches": results["matches"]
    }), 200
