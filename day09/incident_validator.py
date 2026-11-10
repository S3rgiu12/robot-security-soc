
from datetime import datetime
from incident_manager import load_incidents


def validate_incidents():
    incidents = load_incidents()

    errors = []
    ids_seen = set()

    print("=== SECURITY INCIDENT VALIDATOR ===")

    for incident in incidents:
        incident_id = incident.get("incident_id")
        status = incident.get("status")

        if incident_id in ids_seen:
            errors.append(f"{incident_id}: Duplicate incident ID")
        ids_seen.add(incident_id)

        if status not in ("OPEN", "RESOLVED"):
            errors.append(f"{incident_id}: Invalid status")
            continue

        try:
            created = datetime.fromisoformat(
                incident["created_at"]
            )

            resolved = (
                datetime.fromisoformat(incident["resolved_at"])
                if incident.get("resolved_at")
                else None
            )

            if resolved:
                # Both timestamps must use the same timezone convention
                if (created.tzinfo is None) != (resolved.tzinfo is None):
                    errors.append(
                        f"{incident_id}: Mixed timezone conventions"
                    )
                elif resolved < created:
                    errors.append(
                        f"{incident_id}: Resolution before creation"
                    )

            if status == "RESOLVED" and resolved is None:
                errors.append(
                    f"{incident_id}: Missing resolution timestamp"
                )

            if status == "OPEN" and resolved is not None:
                errors.append(
                    f"{incident_id}: OPEN incident has resolution timestamp"
                )

        except (ValueError, TypeError, KeyError) as error:
            errors.append(
                f"{incident_id}: Invalid timestamp ({error})"
            )

    print(f"Total incidents checked: {len(incidents)}")
    print(f"Validation errors: {len(errors)}")

    if errors:
        print("\nDetected problems:")
        for error in errors:
            print(f"[ERROR] {error}")
    else:
        print("[OK] All incidents passed validation.")


if __name__ == "__main__":
    validate_incidents()
