from flask import Blueprint, jsonify

from flask_session_auth import (
    require_analyst,
    current_analyst
)

from incident_priority_engine import prioritize_incidents


incident_priority_bp = Blueprint(
    "incident_priority",
    __name__
)


@incident_priority_bp.route(
    "/api/day20/incident-priorities",
    methods=["GET"]
)
@require_analyst
def get_incident_priorities():

    user = current_analyst()

    if user is None or user.get("role") != "ANALYST":
        return jsonify({
            "error": "Analyst role required"
        }), 403

    results = prioritize_incidents()

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for incident in results:
        summary[incident["priority"]] += 1

    return jsonify({
        "status": "OK",
        "total_incidents": len(results),
        "priority_summary": summary,
        "incidents": results
    }), 200
