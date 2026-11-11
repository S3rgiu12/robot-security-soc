from soc_reports_reader_day17 import get_soc_reports, get_pdf_path
from forensics_reader_day16 import get_day16_forensics
from investigation_reader import get_incident_investigations
from correlation_reader import get_correlated_incidents

from flask import Flask, render_template, jsonify, send_file
from datetime import datetime
from ids_log_reader import get_ids_summary
from availability_log_reader import get_availability_summary
import sys
from pathlib import Path
from incident_reader import get_incidents_summary
from recovery_reader import get_recovery_summary
from security_alert_reader import get_security_alerts
from flask import request
import sys
from pathlib import Path

from alert_auth import verify_alert_token
from alert_management_reader import (
    get_alert_management,
    get_security_notifications
)

DAY07_DIR = Path(__file__).resolve().parent.parent / "day07"

if str(DAY07_DIR) not in sys.path:
    sys.path.insert(0, str(DAY07_DIR))

from heartbeat_reader import get_heartbeat_status
DAY13_DIR = Path(__file__).resolve().parent.parent / "day13"

if str(DAY13_DIR) not in sys.path:
    sys.path.insert(0, str(DAY13_DIR))

from alert_lifecycle_manager import update_alert
app = Flask(__name__)

# SOC_AUTH_INTEGRATION_V1
from datetime import timedelta

SOC_AUTH_DIR = (
    Path(__file__).resolve().parent.parent
    / "day18" / "auth"
)

if str(SOC_AUTH_DIR) not in sys.path:
    sys.path.insert(0, str(SOC_AUTH_DIR))

from soc_auth_api import soc_auth_bp

secret_file = SOC_AUTH_DIR / ".env.auth"

if not secret_file.is_file():
    raise RuntimeError("SOC authentication secret missing")

secret_values = {}

for line in secret_file.read_text(
    encoding="utf-8"
).splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        secret_values[key.strip()] = value.strip()

secret_key = secret_values.get(
    "SOC_FLASK_SECRET_KEY"
)

if not secret_key or len(secret_key) < 64:
    raise RuntimeError("Invalid SOC Flask secret")

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# DAY29_SECURITY_HEADERS
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

app.register_blueprint(soc_auth_bp)

# DAY19_ANALYST_OPERATIONS_INTEGRATION
DAY19_DIR = Path(__file__).resolve().parent.parent / "day19"
DAY18_DIR = Path(__file__).resolve().parent.parent / "day18"

for directory in (DAY18_DIR, DAY19_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from analyst_operations_api import analyst_operations_bp
app.register_blueprint(analyst_operations_bp)

# Day 20 - Automated Incident Prioritization
DAY20_DIR = Path(__file__).resolve().parent.parent / "day20"

if str(DAY20_DIR) not in sys.path:
    sys.path.insert(0, str(DAY20_DIR))

from incident_priority_api import incident_priority_bp

app.register_blueprint(incident_priority_bp)

# DAY 21 - Threat Intelligence IOC Correlation
DAY21_DIR = Path(__file__).resolve().parent.parent / "day21"

if str(DAY21_DIR) not in sys.path:
    sys.path.insert(0, str(DAY21_DIR))

from ioc_correlation_api import ioc_correlation_bp

app.register_blueprint(ioc_correlation_bp)

# DAY 22 - SOC Threat Alert Enrichment
DAY22_DIR = Path(__file__).resolve().parent.parent / "day22"

if str(DAY22_DIR) not in sys.path:
    sys.path.insert(0, str(DAY22_DIR))

from threat_alert_api import threat_alert_bp

app.register_blueprint(threat_alert_bp)



# DAY23_SOC_INVESTIGATION_INTEGRATION
DAY23_DIR = Path(__file__).resolve().parent.parent / "day23"

if str(DAY23_DIR) not in sys.path:
    sys.path.insert(0, str(DAY23_DIR))

from investigation_api import investigation_bp

app.register_blueprint(investigation_bp)

# END_DAY23_SOC_INVESTIGATION_INTEGRATION

# DAY24_THREAT_HUNTING_TIMELINE_INTEGRATION
DAY24_DIR = Path(__file__).resolve().parent.parent / "day24"

if str(DAY24_DIR) not in sys.path:
    sys.path.insert(0, str(DAY24_DIR))

from investigation_timeline_api import timeline_bp

app.register_blueprint(timeline_bp)

# END_DAY24_THREAT_HUNTING_TIMELINE_INTEGRATION



# END_DAY19_ANALYST_OPERATIONS_INTEGRATION


# END_SOC_AUTH_INTEGRATION_V1




# SOC_READ_API_ACCESS_CONTROL_V1
SOC_PROTECTED_READ_ENDPOINTS = {
    "ids_api",
    "heartbeat_api",
    "availability_events_api",
    "api_incidents",
    "api_recovery",
    "api_security_alerts",
    "api_alert_management",
    "api_security_notifications",
    "incident_investigations_api",
    "correlated_incidents_api",
    "day16_forensics_api",
    "day17_soc_reports_api",
    "day17_soc_report_pdf_api",
    "day18_analyst_cases_api",
    "day18_analyst_audit_api",
}

from flask import jsonify as soc_jsonify
from flask_session_auth import current_analyst as soc_current_analyst

@app.before_request
def soc_read_api_access_control():
    if request.endpoint not in SOC_PROTECTED_READ_ENDPOINTS:
        return None

    if request.method != "GET":
        return None

    if soc_current_analyst() is None:
        return soc_jsonify({
            "error": "authentication_required"
        }), 401

    return None

@app.route("/")
def dashboard():
    from flask_session_auth import current_analyst
    from flask import redirect, url_for

    if current_analyst() is None:
        return redirect(url_for("soc_login_page"))

    summary = get_ids_summary()

    return render_template(
        "dashboard.html",
        title="Robot Security Dashboard",
        current_time=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        summary=summary
    )


@app.route("/api/ids")
def ids_api():
    return jsonify(get_ids_summary())

@app.route("/api/heartbeat")
def heartbeat_api():
    return jsonify(get_heartbeat_status())

@app.route("/api/availability-events")
def availability_events_api():
    return jsonify(get_availability_summary())

@app.route("/health")
def health():
    return {
        "status": "ok",
        "service": "Robot Security Dashboard"
    }

@app.route("/api/incidents")
def api_incidents():
    try:
        return jsonify(get_incidents_summary())
    except (OSError, ValueError) as error:
        app.logger.error("Incident API error: %s", error)
        return jsonify({
            "error": "Unable to read incident registry"
        }), 500

@app.route("/api/recovery")
def api_recovery():
    return jsonify(get_recovery_summary())
@app.route("/api/security-alerts", methods=["GET"])
def api_security_alerts():
    severity = request.args.get("severity")

    try:
        limit = int(request.args.get("limit", "100"))
        return jsonify(
            get_security_alerts(
                severity=severity,
                limit=limit
            )
        )
    except ValueError as exc:
        return jsonify({
            "status": "ERROR",
            "message": str(exc)
        }), 400
    except (OSError, json.JSONDecodeError):
        app.logger.exception("Cannot read security alerts")
        return jsonify({
            "status": "ERROR",
            "message": "Alert registry unavailable"
        }), 503

@app.route("/api/alert-management", methods=["GET"])
def api_alert_management():
    try:
        return jsonify(get_alert_management())
    except (OSError, ValueError, KeyError) as error:
        app.logger.error("Alert management error: %s", error)
        return jsonify({
            "status": "ERROR",
            "message": "Unable to load alert management data"
        }), 500


@app.route("/api/security-notifications", methods=["GET"])
def api_security_notifications():
    try:
        return jsonify(get_security_notifications())
    except (OSError, ValueError, KeyError) as error:
        app.logger.error("Security notifications error: %s", error)
        return jsonify({
            "status": "ERROR",
            "message": "Unable to load notification data"
        }), 500

@app.route("/api/alert-management/acknowledge", methods=["POST"])
@app.route("/api/alert-management/resolve", methods=["POST"])
def api_update_alert():
    # Token supplied through a custom HTTP header.
    token = request.headers.get("X-Alert-Token", "")

    try:
        authorized = verify_alert_token(token)
    except RuntimeError:
        app.logger.exception("Alert authentication unavailable")
        return jsonify({
            "status": "ERROR",
            "message": "Authentication unavailable"
        }), 503

    # Permit either the existing service token or
    # an authenticated analyst with a valid CSRF token.
    if not authorized:
        from soc_alert_authorization import analyst_can_update_alert

        if not analyst_can_update_alert():
            return jsonify({
                "status": "ERROR",
                "message": "Unauthorized"
            }), 401

    if not request.is_json:
        return jsonify({
            "status": "ERROR",
            "message": "JSON body required"
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "status": "ERROR",
            "message": "Invalid JSON body"
        }), 400

    alert_id = data.get("alert_id")
    note = data.get("note")

    if not isinstance(alert_id, str) or not alert_id.strip():
        return jsonify({
            "status": "ERROR",
            "message": "Valid alert_id required"
        }), 400

    if note is not None and not isinstance(note, str):
        return jsonify({
            "status": "ERROR",
            "message": "Note must be a string"
        }), 400

    action = (
        "acknowledge"
        if request.path.endswith("/acknowledge")
        else "resolve"
    )

    try:
        result = update_alert(
            alert_id.strip(),
            action,
            note
        )

        return jsonify({
            "status": "OK",
            "action": action,
            "alert": result
        }), 200

    except ValueError as error:
        return jsonify({
            "status": "ERROR",
            "message": str(error)
        }), 400

    except OSError:
        app.logger.exception("Alert registry update failed")
        return jsonify({
            "status": "ERROR",
            "message": "Registry update failed"
        }), 500





@app.route("/api/incident-investigations", methods=["GET"])
def incident_investigations_api():
    result = get_incident_investigations()

    if result["status"] == "OK":
        return jsonify(result), 200

    if result["status"] == "UNAVAILABLE":
        return jsonify(result), 503

    return jsonify(result), 500

@app.route("/api/correlated-incidents", methods=["GET"])
def correlated_incidents_api():
    result = get_correlated_incidents()

    status = result.get("status")

    if status == "OK":
        return jsonify(result), 200

    if status == "UNAVAILABLE":
        return jsonify(result), 503

    return jsonify(result), 500



@app.route("/api/day16-forensics", methods=["GET"])
def day16_forensics_api():
    result = get_day16_forensics()

    if result.get("status") == "OK":
        return jsonify(result), 200

    return jsonify(result), 503




# DAY 17 — SOC INCIDENT REPORTS

@app.route("/api/day17-soc-reports", methods=["GET"])
def day17_soc_reports_api():
    result = get_soc_reports()

    if result.get("status") == "OK":
        return jsonify(result), 200

    return jsonify(result), 503


@app.route(
    "/api/day17-soc-reports/<incident_id>/pdf",
    methods=["GET"]
)
def day17_soc_report_pdf_api(incident_id):
    path = get_pdf_path(incident_id)

    if path is None:
        return jsonify({
            "status": "NOT_FOUND",
            "error": "SOC report not found"
        }), 404

    return send_file(
        path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=path.name
    )


# DAY 18 — SOC ANALYST WORKFLOW (READ ONLY)

from analyst_workflow_reader_day18 import (
    get_analyst_cases,
    get_analyst_audit
)


@app.route("/api/day18-analyst-cases", methods=["GET"])
def day18_analyst_cases_api():
    try:
        return jsonify(get_analyst_cases()), 200
    except Exception:
        app.logger.exception("Day 18 cases read failed")
        return jsonify({
            "status": "ERROR",
            "error": "Analyst cases unavailable"
        }), 503


@app.route(
    "/api/day18-analyst-cases/<incident_id>/audit",
    methods=["GET"]
)
def day18_analyst_audit_api(incident_id):
    try:
        return jsonify(get_analyst_audit(incident_id)), 200
    except ValueError:
        return jsonify({
            "status": "NOT_FOUND",
            "error": "Invalid or unknown incident"
        }), 404
    except Exception:
        app.logger.exception("Day 18 audit read failed")
        return jsonify({
            "status": "ERROR",
            "error": "Analyst audit unavailable"
        }), 503




@app.route("/soc-login", methods=["GET"])
def soc_login_page():
    return render_template("soc_login.html")



# DAY25_INCIDENT_CASE_MANAGEMENT_INTEGRATION
import sys
from pathlib import Path

DAY25_PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(DAY25_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(DAY25_PROJECT_ROOT))

from day25.incident_case_api import incident_case_bp

app.register_blueprint(incident_case_bp)

# Day 26 - SOC Incident Reporting
from day26.incident_report_api import incident_report_bp

app.register_blueprint(incident_report_bp)

# DAY27_SECURE_INTEGRITY_INTEGRATION
from day27.incident_integrity_api import integrity_bp
app.register_blueprint(integrity_bp)
# END_DAY27_SECURE_INTEGRITY_INTEGRATION

# DAY28_SIGNED_BUNDLE_INTEGRATION
from day28.signed_bundle_api import signed_bundle_bp
app.register_blueprint(signed_bundle_bp)
# END_DAY28_SIGNED_BUNDLE_INTEGRATION




app.config.setdefault(
    "DAY25_INCIDENT_DB",
    str(
        Path(__file__).resolve().parent.parent
        / "day25/data/soc_incident_cases.db"
    ),
)
# END_DAY25_INCIDENT_CASE_MANAGEMENT_INTEGRATION

if __name__ == "__main__":
    print("=== ROBOT SECURITY DASHBOARD ===")
    print("Starting Flask server...")
    print("Listening on http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

