from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "soc_alert_investigations.db"

VALID_STATUSES = (
    "UNREVIEWED",
    "INVESTIGATING",
    "CONFIRMED",
    "FALSE_POSITIVE",
)


def connect_db(db_path=None):
    path = Path(db_path) if db_path else DATABASE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


def initialize_database(db_path=None):
    with connect_db(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_investigations (
                alert_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'UNREVIEWED'
                    CHECK (
                        status IN (
                            'UNREVIEWED',
                            'INVESTIGATING',
                            'CONFIRMED',
                            'FALSE_POSITIVE'
                        )
                    ),
                assigned_analyst TEXT,
                created_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_investigation_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                analyst TEXT NOT NULL,
                action TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                note TEXT,
                created_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (alert_id)
                    REFERENCES alert_investigations(alert_id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_investigation_audit_alert
            ON alert_investigation_audit(alert_id, id)
        """)

    return str(Path(db_path) if db_path else DATABASE_PATH)


if __name__ == "__main__":
    path = initialize_database()
    print("DAY23 DATABASE INITIALIZED")
    print("Database:", path)
    print("Valid statuses:", ", ".join(VALID_STATUSES))
