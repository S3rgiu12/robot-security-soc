from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from day27.secure_bundle_verifier import verify_secure_bundle
from day28.verify_signature import verify_signature

CASE_ID = "INC-CAC40C42F3254074"

MANIFEST = ROOT / "day27" / "exports" / CASE_ID / "manifest.json"
SIGNATURE = ROOT / "day28" / "signatures" / CASE_ID / "manifest.sig"
PUBLIC_KEY = ROOT / "day28" / "keys" / "soc_signing_public.pem"


def main():
    print("=== DAY28 SIGNED INCIDENT BUNDLE VERIFICATION ===")

    # Step 1: Verify exported files against SHA-256 manifest.
    integrity = verify_secure_bundle(CASE_ID)

    integrity_valid = (
        integrity["status"] == "VALID"
        and integrity["verified_count"] == integrity["total_files"]
        and integrity["total_files"] == 3
    )

    print()
    print("SHA-256 integrity:", "VALID" if integrity_valid else "INVALID")
    print(
        "Verified files:",
        f'{integrity["verified_count"]}/{integrity["total_files"]}',
    )

    # Step 2: Verify Ed25519 signature.
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY.read_bytes()
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise SystemExit("Unexpected public key algorithm.")

    manifest_data = MANIFEST.read_bytes()
    signature_data = SIGNATURE.read_bytes()

    signature_valid = (
        len(signature_data) == 64
        and verify_signature(public_key, manifest_data, signature_data)
    )

    print(
        "Ed25519 signature:",
        "VALID" if signature_valid else "INVALID",
    )

    # Step 3: Combined result.
    verified = integrity_valid and signature_valid

    print()
    print(
        "SIGNED BUNDLE STATUS:",
        "SIGNED & VERIFIED" if verified else "VERIFICATION FAILED",
    )

    if not verified:
        raise SystemExit(1)

    print("DAY28 SIGNED BUNDLE VERIFICATION: PASS")


if __name__ == "__main__":
    main()
