
import struct
from pathlib import Path

PCAP_FILE = Path("captures/robot_tls_traffic.pcap")
PORT = 9443
SENSITIVE_MARKER = b"ROBOT_ID="

print("=== ROBOT TLS TRAFFIC SECURITY AUDITOR ===")

def analyze_pcap(path):
    data = path.read_bytes()

    if len(data) < 24:
        raise ValueError("Invalid or empty PCAP file")

    magic = data[:4]

    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }

    if magic not in formats:
        raise ValueError("Unsupported PCAP format")

    endian = formats[magic]

    linktype = struct.unpack_from(endian + "I", data, 20)[0]

    if linktype != 1:
        raise ValueError("Only Ethernet PCAP supported")

    offset = 24
    total_packets = 0
    tcp_packets = 0
    payload_packets = 0
    plaintext_found = False
    tls_records = 0

    while offset + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16

        if offset + incl_len > len(data):
            raise ValueError("Truncated packet data")

        packet = data[offset:offset + incl_len]
        offset += incl_len
        total_packets += 1

        if len(packet) < 14:
            continue

        # Ethernet / IPv4
        if packet[12:14] != b"\x08\x00":
            continue

        ip = packet[14:]

        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue

        ip_header_len = (ip[0] & 0x0F) * 4
        ip_total_len = int.from_bytes(ip[2:4], "big")

        if ip_header_len < 20 or len(ip) < ip_total_len:
            continue

        if ip[9] != 6:
            continue

        if len(ip) < ip_header_len + 20:
            continue

        tcp = ip[ip_header_len:ip_total_len]

        src_port, dst_port = struct.unpack("!HH", tcp[:4])

        if PORT not in (src_port, dst_port):
            continue

        tcp_header_len = (tcp[12] >> 4) * 4

        if tcp_header_len < 20 or len(tcp) < tcp_header_len:
            continue

        tcp_packets += 1

        payload = tcp[tcp_header_len:]

        if not payload:
            continue

        payload_packets += 1

        if SENSITIVE_MARKER in payload:
            plaintext_found = True

        # Basic TLS record identification.
        # This is not full TCP stream reassembly.
        if (
            len(payload) >= 5
            and payload[0] in (20, 21, 22, 23)
            and payload[1] == 3
            and payload[2] in (1, 2, 3, 4)
        ):
            tls_records += 1

    print("\n[1] PACKET STATISTICS")
    print("Total packets:", total_packets)
    print("TCP packets on port 9443:", tcp_packets)
    print("TCP packets with payload:", payload_packets)

    print("\n[2] TLS RECORD CHECK")
    print("TLS record candidates:", tls_records)

    print("\n[3] PLAINTEXT SECURITY CHECK")

    if plaintext_found:
        print("WARNING: Robot telemetry marker visible!")
    else:
        print("PASS: No plaintext telemetry marker detected")

    print("\n[4] SECURITY ASSESSMENT")

    if tcp_packets == 0 or payload_packets == 0:
        print("INCONCLUSIVE: No TCP application traffic")
    elif plaintext_found:
        print("REVIEW REQUIRED: Potential plaintext exposure")
    elif tls_records > 0:
        print("PASS: TLS traffic detected; no plaintext marker")
    else:
        print("INCONCLUSIVE: TLS records not identified")

    print("\nNOTE: This is a basic packet-level audit.")
    print("It does not reassemble TCP streams or prove")
    print("complete confidentiality.")

try:
    analyze_pcap(PCAP_FILE)
except (OSError, ValueError, struct.error) as error:
    print("ERROR:", error)

print("\n=== ANALYSIS COMPLETE ===")
