from flask import Blueprint, jsonify, current_app

from flask_session_auth import (
    require_analyst,
    current_analyst,
)

from evidence_correlation_engine import (
    correlate_evidence,
)

from threat_hunting_engine import REAL_IDS_LOG


timeline_bp = Blueprint(
    "day24_investigation_timeline",
    __name__
)


def analyst_authorized():
    analyst = current_analyst()

    return (
        analyst is not None
        and analyst.get("role") == "ANALYST"
    )


def timeline_source():
    return current_app.config.get(
        "DAY24_TIMELINE_LOG",
        str(REAL_IDS_LOG)
    )


def error_response(message, status):
    return jsonify({"error": message}), status


@timeline_bp.get("/api/day24/timeline")
@require_analyst
def investigation_timeline():
    if not analyst_authorized():
        return error_response(
            "Analyst role required", 403
        )

    try:
        result = correlate_evidence(
            timeline_source()
        )

        return jsonify(result)

    except (OSError, ValueError, KeyError, TypeError):
        current_app.logger.exception(
            "Day24 timeline generation failed"
        )

        return error_response(
            "Investigation timeline unavailable",
            503
        )


@timeline_bp.get(
    "/api/day24/timeline/<alert_id>"
)
@require_analyst
def investigation_timeline_details(alert_id):
    if not analyst_authorized():
        return error_response(
            "Analyst role required", 403
        )

    try:
        result = correlate_evidence(
            timeline_source()
        )

        matching = [
            event
            for event in result["timeline"]
            if event["alert_id"] == alert_id
        ]

        if not matching:
            return error_response(
                "Unknown alert ID", 404
            )

        return jsonify({
            "status": "OK",
            "alert_id": alert_id,
            "total_events": len(matching),
            "timeline": matching,
        })

    except (OSError, ValueError, KeyError, TypeError):
        current_app.logger.exception(
            "Day24 timeline details failed"
        )

        return error_response(
            "Investigation timeline unavailable",
            503
        )
