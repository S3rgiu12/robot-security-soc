import sqlite3
import re
from pathlib import Path

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

AUTH_DB = (
    Path(__file__).resolve().parent
    / "analyst_users.db"
)

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,40}$")


def connect_auth(db_path=AUTH_DB):
    db = sqlite3.connect(str(db_path), timeout=10)
    db.row_factory = sqlite3.Row
    return db


def initialize_auth(db_path=AUTH_DB):
    with connect_auth(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS analyst_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK(role IN ('ANALYST', 'ADMIN')),
                active INTEGER NOT NULL DEFAULT 1
                    CHECK(active IN (0, 1))
            )
        """)


def create_analyst(
    username,
    password,
    role="ANALYST",
    db_path=AUTH_DB
):
    if not isinstance(username, str) or not (
        USERNAME_PATTERN.fullmatch(username)
    ):
        raise ValueError("Invalid username")

    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must have at least 12 characters")

    if role not in ("ANALYST", "ADMIN"):
        raise ValueError("Invalid role")

    password_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    with connect_auth(db_path) as db:
        db.execute("""
            INSERT INTO analyst_users (
                username, password_hash, role, active
            )
            VALUES (?, ?, ?, 1)
        """, (username, password_hash, role))


def authenticate_analyst(
    username,
    password,
    db_path=AUTH_DB
):
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    with connect_auth(db_path) as db:
        row = db.execute("""
            SELECT username, password_hash, role, active
            FROM analyst_users
            WHERE username = ?
        """, (username,)).fetchone()

    if row is None or not row["active"]:
        return None

    if not check_password_hash(row["password_hash"], password):
        return None

    return {
        "username": row["username"],
        "role": row["role"]
    }
