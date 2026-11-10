import secrets
import time
from collections import defaultdict, deque

from flask import Blueprint, jsonify, request, session

from flask_session_auth import (
    login_analyst,
    current_analyst,
    logout_analyst
)

soc_auth_bp = Blueprint("soc_auth", __name__)

WINDOW_SECONDS = 900
MAX_ATTEMPTS = 5

failed_attempts = defaultdict(deque)


def is_rate_limited(key):
    now = time.monotonic()
    attempts = failed_attempts[key]

    while attempts and now - attempts[0] > WINDOW_SECONDS:
        attempts.popleft()

    return len(attempts) >= MAX_ATTEMPTS


@soc_auth_bp.post("/api/soc-auth/login")
def soc_login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid credentials"}), 400

    key = (request.remote_addr, username)

    if is_rate_limited(key):
        return jsonify({
            "error": "Too many login attempts"
        }), 429

    user = login_analyst(username, password)

    if user is None:
        failed_attempts[key].append(time.monotonic())
        return jsonify({"error": "Invalid credentials"}), 401

    failed_attempts.pop(key, None)

    return jsonify({
        "status": "AUTHENTICATED",
        "user": user,
        "csrf_token": session["csrf_token"]
    }), 200


@soc_auth_bp.get("/api/soc-auth/me")
def soc_me():
    user = current_analyst()

    if user is None:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "user": user
    }), 200


@soc_auth_bp.get("/api/soc-auth/csrf")
def soc_csrf():
    user = current_analyst()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    return jsonify({
        "csrf_token": session.get("csrf_token")
    }), 200


@soc_auth_bp.post("/api/soc-auth/logout")
def soc_logout():
    user = current_analyst()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")

    if not expected or not secrets.compare_digest(
        expected, provided
    ):
        return jsonify({"error": "Invalid CSRF token"}), 403

    logout_analyst()

    return jsonify({"status": "LOGGED_OUT"}), 200
