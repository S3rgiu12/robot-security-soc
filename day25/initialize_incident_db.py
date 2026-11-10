"""Initialize Day25 SOC incident database."""

import sqlite3

from day25.incident_case_store import (
    DEFAULT_DB,
    initialize_database,
    initialize_evidence_table,
    connect,
)


def main():
    db = DEFAULT_DB

    print("DAY25 DATABASE INITIALIZATION")
    print("Database:", db)

    initialize_database(db)
    initialize_evidence_table(db)

    with connect(db) as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        required = {
            "incident_cases",
            "incident_case_audit",
            "incident_evidence",
        }

        missing = required - tables

        if missing:
            raise RuntimeError(
                f"Missing database tables: {missing}"
            )

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":
            raise sqlite3.DatabaseError(
                f"SQLite integrity check failed: {integrity}"
            )

        for table in sorted(required):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

            print(f"{table}: {count} records")

    print("SQLite integrity: OK")
    print("DAY25 DATABASE INITIALIZATION: PASS")


if __name__ == "__main__":
    main()
