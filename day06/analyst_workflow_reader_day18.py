import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DAY18_DIR = BASE_DIR / "day18"

if str(DAY18_DIR) not in sys.path:
    sys.path.insert(0, str(DAY18_DIR))

from analyst_workflow_engine import (
    list_cases,
    get_audit,
    validate_incident,
)


def get_analyst_cases():
    return {
        "source": "DAY18_ANALYST_WORKFLOW",
        "total_cases": len(list_cases()),
        "cases": list_cases(),
    }


def get_analyst_audit(incident_id):
    validate_incident(incident_id)

    return {
        "incident_id": incident_id,
        "audit": get_audit(incident_id),
    }


if __name__ == "__main__":
    cases = get_analyst_cases()

    print("=== DAY 18 FLASK READER ===")
    print("Total cases:", cases["total_cases"])

    for case in cases["cases"]:
        print(
            case["incident_id"],
            "|", case["workflow_status"],
            "| Analyst:", case["assigned_to"]
        )

    audit = get_analyst_audit("INC-0001")

    print()
    print("INC-0001 audit records:", len(audit["audit"]))
