from pathlib import Path
from getpass import getpass
import os

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent.parent

CASE_ID = "INC-CAC40C42F3254074"

MANIFEST = ROOT / "day27" / "exports" / CASE_ID / "manifest.json"

PRIVATE_KEY = ROOT / "day28" / "keys" / "soc_signing_private.pem"

SIGNATURE_DIR = ROOT / "day28" / "signatures" / CASE_ID

SIGNATURE_FILE = SIGNATURE_DIR / "manifest.sig"


def main():
    print("=== DAY28 SOC DIGITAL SIGNING ===")

    if not MANIFEST.is_file():
        raise SystemExit("Manifest not found.")

    if not PRIVATE_KEY.is_file():
        raise SystemExit("Private signing key not found.")

    # Read original manifest bytes without modifying the file.
    manifest_data = MANIFEST.read_bytes()

    password = getpass("Signing key password: ")

    try:
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY.read_bytes(),
            password=password.encode("utf-8"),
        )
    except (ValueError, TypeError) as error:
        raise SystemExit(
            "Could not unlock signing key. Check the password."
        ) from error

    # Ed25519 signs the exact original bytes.
    signature = private_key.sign(manifest_data)

    SIGNATURE_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    # Never silently overwrite an existing signature.
    fd = os.open(
        SIGNATURE_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(fd, "wb") as file:
        file.write(signature)

    print("Incident:", CASE_ID)
    print("Signature algorithm: Ed25519")
    print("Signature size:", len(signature), "bytes")
    print("Signature saved successfully.")
    print("Original manifest: unchanged")
    print("DAY28 SIGNING: PASS")


if __name__ == "__main__":
    main()
