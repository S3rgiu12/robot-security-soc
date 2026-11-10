
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

EVIDENCE_DIR = BASE_DIR / "evidence"

SOURCES = {
    "availability_log": PROJECT_DIR / "day08/logs/ids_availability.log",
    "incident_registry": PROJECT_DIR / "day09/data/incidents.json",
    "incident_report": BASE_DIR / "reports/incident_response_report.json"
}


def calculate_sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def collect_evidence():
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    collection_dir = EVIDENCE_DIR / f"collection_{timestamp}"
    collection_dir.mkdir(parents=True, exist_ok=False)

    manifest = {
        "collection_id": timestamp,
        "collected_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "purpose": "Robot IDS Incident Response Investigation",
        "files": []
    }

    for evidence_type, source in SOURCES.items():
        if not source.is_file():
            raise FileNotFoundError(
                f"Required evidence missing: {source}"
            )

        destination = collection_dir / source.name

        shutil.copy2(source, destination)

        original_hash = calculate_sha256(source)
        copied_hash = calculate_sha256(destination)

        if original_hash != copied_hash:
            raise RuntimeError(
                f"Integrity verification failed: {source.name}"
            )

        manifest["files"].append({
            "evidence_type": evidence_type,
            "source_path": str(source),
            "stored_filename": destination.name,
            "sha256": copied_hash,
            "size_bytes": destination.stat().st_size,
            "integrity_verified": True
        })

    manifest_path = collection_dir / "evidence_manifest.json"

    with manifest_path.open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4, ensure_ascii=False)

    return collection_dir, manifest


if __name__ == "__main__":
    directory, manifest = collect_evidence()

    print("=== ROBOT SECURITY EVIDENCE COLLECTOR ===")
    print("Collection:", directory.name)
    print("Collected files:", len(manifest["files"]))

    for item in manifest["files"]:
        print(
            f"[OK] {item['stored_filename']} | "
            f"SHA256: {item['sha256'][:16]}..."
        )

    print("Evidence manifest: CREATED")
