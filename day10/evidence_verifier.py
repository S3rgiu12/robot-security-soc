
import hashlib
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = BASE_DIR / "evidence"


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_collection(collection_dir):
    manifest_path = collection_dir / "evidence_manifest.json"

    if not manifest_path.is_file():
        raise FileNotFoundError("Evidence manifest missing")

    with manifest_path.open(encoding="utf-8") as file:
        manifest = json.load(file)

    files = manifest["files"]
    errors = 0

    print("=== ROBOT SECURITY EVIDENCE VERIFIER ===")
    print("Collection:", collection_dir.name)

    for item in files:
        filename = item["stored_filename"]

        # Prevent paths outside the collection directory
        if Path(filename).name != filename:
            print("[FAIL] Invalid filename:", filename)
            errors += 1
            continue

        path = collection_dir / filename

        if not path.is_file() or path.is_symlink():
            print("[FAIL] Missing or invalid:", filename)
            errors += 1
            continue

        actual_hash = sha256_file(path)
        expected_hash = item["sha256"]

        if actual_hash != expected_hash:
            print("[FAIL] Hash mismatch:", filename)
            errors += 1
        elif path.stat().st_size != item["size_bytes"]:
            print("[FAIL] Size mismatch:", filename)
            errors += 1
        else:
            print("[OK]", filename)

    print("Verified files:", len(files))
    print("Verification errors:", errors)

    return errors == 0


if __name__ == "__main__":
    collections = sorted(
        path for path in EVIDENCE_DIR.glob("collection_*")
        if path.is_dir()
    )

    if not collections:
        print("No evidence collections found")
        sys.exit(1)

    latest_collection = collections[-1]
    success = verify_collection(latest_collection)

    print(
        "Final status:",
        "INTEGRITY VERIFIED" if success else "INTEGRITY FAILED"
    )

    sys.exit(0 if success else 1)
