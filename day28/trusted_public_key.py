"""Validate the trusted Ed25519 public key fingerprint."""

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from day27.report_integrity import ReportIntegrityError
from day28.secure_crypto_reader import read_trusted_public_key
from day28.trusted_key_config import TRUSTED_PUBLIC_KEY_SHA256


def load_pinned_public_key(path):
    """Load an Ed25519 key only if its fingerprint is trusted."""

    try:
        pem_data = read_trusted_public_key(path)

        public_key = serialization.load_pem_public_key(pem_data)

    except (OSError, ValueError, TypeError) as exc:
        raise ReportIntegrityError(
            "Cannot load trusted public key"
        ) from exc

    if not isinstance(public_key, Ed25519PublicKey):
        raise ReportIntegrityError(
            "Unexpected public key algorithm"
        )

    der_data = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    actual_fingerprint = hashlib.sha256(der_data).hexdigest()

    if not hmac.compare_digest(
        actual_fingerprint,
        TRUSTED_PUBLIC_KEY_SHA256,
    ):
        raise ReportIntegrityError(
            "Public key fingerprint mismatch"
        )

    return public_key
