
import getpass
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AUTH_DIR = ROOT / "day18" / "auth"

sys.path.insert(0, str(AUTH_DIR))

from analyst_auth import (
    initialize_auth,
    create_analyst,
)

SECRET_FILE = AUTH_DIR / ".env.auth"


def main():
    print("=== Robot Security SOC Setup ===")

    if SECRET_FILE.exists():
        print("Existing Flask secret preserved.")
    else:
        secret = secrets.token_hex(32)
        SECRET_FILE.write_text(
            f"SOC_FLASK_SECRET_KEY={secret}\n",
            encoding="utf-8",
        )
        SECRET_FILE.chmod(0o600)
        print("Flask secret generated.")

    initialize_auth()
    print("Authentication database initialized.")

    username = input("Admin username: ").strip()

    password = getpass.getpass(
        "Admin password (minimum 12 characters): "
    )
    confirm = getpass.getpass(
        "Confirm password: "
    )

    if password != confirm:
        print("Passwords do not match.")
        return

    try:
        create_analyst(
            username=username,
            password=password,
            role="ADMIN",
        )
    except (ValueError, __import__("sqlite3").IntegrityError) as exc:
        print(f"Account creation failed: {exc}")
        return

    print("SOC administrator created successfully.")
    print("Setup completed.")


if __name__ == "__main__":
    main()
