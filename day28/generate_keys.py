from pathlib import Path
from getpass import getpass
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_DIR = Path(__file__).resolve().parent / "keys"
PRIVATE_FILE = KEY_DIR / "soc_signing_private.pem"
PUBLIC_FILE = KEY_DIR / "soc_signing_public.pem"


def main():
    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    if PRIVATE_FILE.exists() or PUBLIC_FILE.exists():
        raise SystemExit("Keys already exist. Refusing to overwrite.")

    password = getpass("New signing key password: ")
    confirmation = getpass("Confirm password: ")

    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    if len(password) < 16:
        raise SystemExit("Use a password of at least 16 characters.")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    fd = os.open(
        PRIVATE_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(fd, "wb") as file:
        file.write(private_pem)

    fd = os.open(
        PUBLIC_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )

    with os.fdopen(fd, "wb") as file:
        file.write(public_pem)

    print("Ed25519 key pair generated successfully.")
    print("Private key: encrypted")
    print("Public key: available for verification")
    print("Existing Day27 bundles: unchanged")


if __name__ == "__main__":
    main()
