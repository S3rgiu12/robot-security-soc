import json
import re
from pathlib import Path
from ipaddress import ip_address

ROOT = Path(__file__).resolve().parent.parent

IOC_FILE = ROOT / "day21/data/ioc_registry.json"
SECURITY_LOG = ROOT / "day05/logs/robot_security.log"

IP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])"
)

DOMAIN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
    r"(?![A-Za-z0-9_.-])"
)


def load_indicators(path=IOC_FILE):
    data = json.loads(
        Path(path).read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("Invalid IOC registry")

    indicators = data.get("indicators")

    if not isinstance(indicators, list):
        raise ValueError("IOC indicators must be a list")

    validated = []
    seen = set()

    for indicator in indicators:
        if not isinstance(indicator, dict):
            raise ValueError("Invalid IOC entry")

        ioc_type = indicator.get("type")
        value = indicator.get("value")

        if not isinstance(value, str) or not value:
            raise ValueError("Invalid IOC value")

        if ioc_type == "ipv4":
            address = ip_address(value)

            if address.version != 4:
                raise ValueError("Expected IPv4 indicator")

            value = str(address)

        elif ioc_type == "domain":
            value = value.lower().rstrip(".")

            if not DOMAIN_PATTERN.fullmatch(value):
                raise ValueError("Invalid domain indicator")

        else:
            raise ValueError("Unsupported IOC type")

        key = (ioc_type, value)

        if key in seen:
            raise ValueError("Duplicate IOC indicator")

        seen.add(key)

        validated.append({
            **indicator,
            "value": value
        })

    return validated


def extract_observables(line):
    addresses = set()
    domains = set()

    for match in IP_PATTERN.finditer(line):
        candidate = match.group()

        try:
            address = ip_address(candidate)

            if address.version == 4:
                addresses.add(str(address))

        except ValueError:
            continue

    for match in DOMAIN_PATTERN.finditer(line):
        candidate = match.group().lower()

        try:
            ip_address(candidate)
            continue
        except ValueError:
            pass

        domains.add(candidate)

    return {
        "ipv4": addresses,
        "domain": domains
    }


def correlate_lines(lines, indicators):
    matches = []

    for line_number, line in enumerate(lines, start=1):
        observables = extract_observables(line)

        for indicator in indicators:
            ioc_type = indicator["type"]
            value = indicator["value"]

            if value not in observables[ioc_type]:
                continue

            matches.append({
                "line_number": line_number,
                "ioc_id": indicator["ioc_id"],
                "ioc_type": ioc_type,
                "ioc_value": value,
                "severity": indicator["severity"],
                "confidence": indicator["confidence"],
                "threat_type": indicator["threat_type"],
                "evidence": line.strip()
            })

    return matches


def correlate_log(
    log_path=SECURITY_LOG,
    ioc_path=IOC_FILE
):
    indicators = load_indicators(ioc_path)

    with Path(log_path).open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as log_file:
        lines = log_file.readlines()

    matches = correlate_lines(lines, indicators)

    return {
        "total_lines": len(lines),
        "total_indicators": len(indicators),
        "total_matches": len(matches),
        "matches": matches
    }


if __name__ == "__main__":
    results = correlate_log()

    print("=== DAY 21 IOC CORRELATION ===")
    print("Log lines:", results["total_lines"])
    print("IOC indicators:", results["total_indicators"])
    print("Matches:", results["total_matches"])

    for match in results["matches"]:
        print(
            match["ioc_id"],
            "|",
            match["ioc_value"],
            "|",
            match["severity"]
        )
