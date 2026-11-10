from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parent.parent
CASE_ID = "INC-CAC40C42F3254074"

MANIFEST = ROOT / "day27" / "exports" / CASE_ID / "manifest.json"
SIGNATURE = ROOT / "day28" / "signatures" / CASE_ID / "manifest.sig"
PUBLIC_KEY = ROOT / "day28" / "keys" / "soc_signing_public.pem"


def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def main():
    print("=== DAY28 ED25519 SIGNATURE VERIFICATION ===")

    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY.read_bytes()
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise SystemExit("Unexpected public key algorithm.")

    manifest_data = MANIFEST.read_bytes()
    signature_data = SIGNATURE.read_bytes()

    if len(signature_data) != 64:
        raise SystemExit("Invalid Ed25519 signature length.")

    valid = verify_signature(
        public_key,
        manifest_data,
        signature_data,
    )

    print("Incident:", CASE_ID)
    print("Signature algorithm: Ed25519")
    print("Original manifest signature:", "VALID" if valid else "INVALID")

    if not valid:
        raise SystemExit("DAY28 VERIFICATION: FAIL")

    print()
    print("=== TAMPERING DETECTION TEST ===")

    # Modify bytes only in memory.
    # The original manifest on disk remains unchanged.
    modified_manifest = manifest_data + b"\nUNAUTHORIZED CHANGE"

    tampered_valid = verify_signature(
        public_key,
        modified_manifest,
        signature_data,
    )

    print(
        "Modified manifest signature:",
        "VALID" if tampered_valid else "INVALID",
    )

    if tampered_valid:
        raise SystemExit("TAMPERING DETECTION: FAIL")

    print("Tampering detected: YES")
    print("Original files: unchanged")
    print()
    print("DAY28 SIGNATURE VERIFICATION: PASS")


if __name__ == "__main__":
    main()
