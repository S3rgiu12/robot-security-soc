"""Day 27 - SOC Report Integrity Engine."""

import hashlib
import hmac
from pathlib import Path


class ReportIntegrityError(ValueError):
    """Invalid report or integrity input."""


def sha256_bytes(data):
    """Calculate SHA-256 for exact bytes."""
    if not isinstance(data, bytes):
        raise ReportIntegrityError(
            "Expected bytes"
        )

    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    """Calculate SHA-256 for UTF-8 text."""
    if not isinstance(text, str):
        raise ReportIntegrityError(
            "Expected text"
        )

    return sha256_bytes(text.encode("utf-8"))


def sha256_file(file_path):
    """Calculate SHA-256 without loading entire file."""
    path = Path(file_path)

    if not path.is_file():
        raise ReportIntegrityError(
            "Report file not found"
        )

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sha256(data, expected_hash):
    """Verify exact bytes against a trusted SHA-256."""
    if not isinstance(data, bytes):
        raise ReportIntegrityError(
            "Expected bytes"
        )

    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(
            char not in "0123456789abcdefABCDEF"
            for char in expected_hash
        )
    ):
        raise ReportIntegrityError(
            "Invalid SHA-256 hash"
        )

    actual_hash = sha256_bytes(data)

    return hmac.compare_digest(
        actual_hash,
        expected_hash.lower(),
    )


def verify_file(file_path, expected_hash):
    """Verify a file against a trusted SHA-256."""
    actual_hash = sha256_file(file_path)

    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(
            char not in "0123456789abcdefABCDEF"
            for char in expected_hash
        )
    ):
        raise ReportIntegrityError(
            "Invalid SHA-256 hash"
        )

    return hmac.compare_digest(
        actual_hash,
        expected_hash.lower(),
    )
