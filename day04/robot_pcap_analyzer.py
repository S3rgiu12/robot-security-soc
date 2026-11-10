
import subprocess
import re
from collections import Counter
from pathlib import Path

PCAP = Path("robot_traffic.pcap")

print("=== ROBOT PCAP SECURITY ANALYZER v1 ===")

if not PCAP.is_file():
    print("ERROR: PCAP file not found.")
    raise SystemExit(1)

result = subprocess.run(
    ["tcpdump", "-nn", "-A", "-r", str(PCAP)],
    capture_output=True,
    text=True,
    errors="replace"
)

if result.returncode != 0:
    print("ERROR:", result.stderr.strip())
    raise SystemExit(1)

output = result.stdout

packet_lines = [
    line for line in output.splitlines()
    if re.match(r"^\d{2}:\d{2}:\d{2}\.\d+ IP ", line)
]

flags = Counter()
client_ports = set()

for line in packet_lines:
    match = re.search(r"Flags \[([^\]]+)\]", line)
    if match:
        flags[match.group(1)] += 1

    match = re.search(
        r"127\.0\.0\.1\.(\d+) > 127\.0\.0\.1\.9000:",
        line
    )
    if match:
        client_ports.add(int(match.group(1)))

telemetry_count = output.count("ROBOT_ID=R001;")
response_count = output.count("Telemetry received")

print("\n[1] PACKET STATISTICS")
print("Total TCP packets:", len(packet_lines))
print("Client ports:", sorted(client_ports))

print("\n[2] TCP FLAGS")
for flag, count in sorted(flags.items()):
    print(f"Flags [{flag}]: {count}")

print("\n[3] ROBOT TELEMETRY")
print("Telemetry messages:", telemetry_count)
print("Server responses:", response_count)

print("\n[4] SECURITY CHECK")
if telemetry_count > 0:
    print("WARNING: Robot telemetry visible in plaintext!")
    print("RECOMMENDATION: Implement TLS encryption.")
else:
    print("No matching plaintext telemetry detected.")

print("\n=== ANALYSIS COMPLETE ===")
