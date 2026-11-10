"""Day 27 - Descriptor-based SOC bundle verification."""

import hmac
import json

from day27.bundle_access import EXPORT_ROOT
from day27.manifest_security import validate_manifest
from day27.report_integrity import ReportIntegrityError
from day27.report_manifest import EXPORT_NAMES
from day27.secure_bundle_fd import open_secure_bundle
from day27.secure_bundle_files import (
    read_bundle_file,
    hash_bundle_file,
)


def verify_secure_bundle(case_id, export_root=EXPORT_ROOT):
    """Verify all exports relative to one open bundle directory."""

    with open_secure_bundle(case_id, export_root) as bundle_fd:
        raw_manifest = read_bundle_file(
            bundle_fd,
            "manifest.json",
        )

        try:
            manifest = json.loads(
                raw_manifest.decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReportIntegrityError(
                "Invalid manifest JSON"
            ) from exc

        validate_manifest(
            manifest,
            expected_case_id=case_id,
        )

        results = {}

        for filename in EXPORT_NAMES:
            expected = manifest["files"][filename]

            try:
                actual = hash_bundle_file(
                    bundle_fd,
                    filename,
                )

                results[filename] = (
                    actual["size_bytes"]
                    == expected["size_bytes"]
                    and hmac.compare_digest(
                        actual["sha256"],
                        expected["sha256"].lower(),
                    )
                )

            except ReportIntegrityError:
                results[filename] = False

        return {
            "case_id": case_id,
            "status": (
                "VALID"
                if all(results.values())
                else "TAMPERED"
            ),
            "files": results,
            "verified_count": sum(results.values()),
            "total_files": len(results),
        }
