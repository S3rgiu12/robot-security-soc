"""Day 28 - Secure Ed25519 + SHA-256 bundle verification."""

import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from day27.bundle_access import EXPORT_ROOT
from day27.manifest_security import validate_manifest
from day27.report_integrity import ReportIntegrityError
from day27.report_manifest import EXPORT_NAMES
from day27.secure_bundle_fd import open_secure_bundle
from day27.secure_bundle_files import read_bundle_file
from day28.trusted_public_key import load_pinned_public_key
from day28.secure_crypto_reader import (
    read_trusted_public_key,
    read_detached_signature,
)


ROOT = Path(__file__).resolve().parent.parent

PUBLIC_KEY_FILE = (
    ROOT / "day28" / "keys" / "soc_signing_public.pem"
)

SIGNATURE_ROOT = ROOT / "day28" / "signatures"


def verify_signed_bundle(
    case_id,
    export_root=EXPORT_ROOT,
    public_key_file=PUBLIC_KEY_FILE,
    signature_root=SIGNATURE_ROOT,
):
    """Verify a signed incident bundle using one manifest snapshot."""

    with open_secure_bundle(case_id, export_root) as bundle_fd:

        # Read the original manifest exactly once.
        raw_manifest = read_bundle_file(
            bundle_fd,
            "manifest.json",
        )

        try:
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReportIntegrityError(
                "Invalid manifest JSON"
            ) from exc

        validate_manifest(
            manifest,
            expected_case_id=case_id,
        )

        # Load and validate the pinned Ed25519 public key.
        public_key = load_pinned_public_key(public_key_file)

        # Load detached Ed25519 signature.
        signature_file = (
            Path(signature_root) / case_id / "manifest.sig"
        )

        try:
            signature = read_detached_signature(case_id, signature_root)
        except OSError as exc:
            raise ReportIntegrityError(
                "Cannot read manifest signature"
            ) from exc

        signature_valid = False

        if len(signature) == 64:
            try:
                public_key.verify(signature, raw_manifest)
                signature_valid = True
            except InvalidSignature:
                pass

        # Do not trust manifest hashes unless signature is valid.
        results = {}

        if signature_valid:
            for filename in EXPORT_NAMES:
                expected = manifest["files"][filename]

                try:
                    data = read_bundle_file(bundle_fd, filename)

                    actual_hash = hashlib.sha256(data).hexdigest()

                    results[filename] = (
                        len(data) == expected["size_bytes"]
                        and hmac.compare_digest(
                            actual_hash,
                            expected["sha256"].lower(),
                        )
                    )

                except ReportIntegrityError:
                    results[filename] = False

        else:
            results = {
                filename: False
                for filename in EXPORT_NAMES
            }

        integrity_valid = all(results.values())

        verified = signature_valid and integrity_valid

        return {
            "case_id": case_id,
            "signature_algorithm": "Ed25519",
            "hash_algorithm": "SHA-256",
            "signature_status": (
                "VALID" if signature_valid else "INVALID"
            ),
            "integrity_status": (
                "VALID" if integrity_valid and signature_valid
                else "INVALID"
            ),
            "files": results,
            "verified_count": sum(results.values()),
            "total_files": len(results),
            "status": (
                "SIGNED & VERIFIED"
                if verified
                else "VERIFICATION FAILED"
            ),
        }
