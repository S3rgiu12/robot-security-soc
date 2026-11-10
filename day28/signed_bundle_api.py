"""Day 28 - Authenticated signed incident verification API."""

from flask import Blueprint, jsonify, make_response
from flask_session_auth import require_analyst

from day27.incident_integrity_api import (
    require_integrity_role,
    secure_response,
    integrity_error,
)
from day27.manifest_security import validate_case_id
from day27.report_integrity import ReportIntegrityError
from day28.secure_signed_bundle_verifier import verify_signed_bundle


signed_bundle_bp = Blueprint(
    "day28_signed_bundle",
    __name__,
)



@signed_bundle_bp.after_request
def secure_signed_bundle_response(response):
    """Prevent caching of incident verification responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@signed_bundle_bp.get(
    "/api/day28/incidents/<case_id>/signature"
)
@require_analyst
@require_integrity_role
def incident_signature(case_id):
    """Verify incident authenticity and integrity."""

    try:
        validate_case_id(case_id)
    except ReportIntegrityError:
        return integrity_error(
            "Invalid incident case ID", 400
        )

    try:
        result = verify_signed_bundle(case_id)
    except ReportIntegrityError:
        return integrity_error(
            "Signed incident bundle unavailable or invalid",
            422,
        )

    response = jsonify(result)
    return secure_response(response), 200
