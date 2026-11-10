
import socket
import ssl

HOST = "127.0.0.1"
PORT = 9555
TRUSTED_CERT = "certs/server.crt"

TELEMETRY = "ROBOT_ID=R001;BATTERY=85;TEMP=42"


def test_robot_connection(mode, context):
    print(f"\n=== {mode} ROBOT CLIENT ===")

    try:
        with socket.create_connection(
            (HOST, PORT), timeout=5
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=HOST
            ) as tls_sock:

                print("TLS connection established!")
                print("Protocol:", tls_sock.version())
                print("Cipher:", tls_sock.cipher()[0])

                tls_sock.sendall(TELEMETRY.encode())
                print("Telemetry sent:", TELEMETRY)

                response = tls_sock.recv(4096)
                print("Server response:", response.decode())

    except ssl.SSLCertVerificationError as error:
        print("SECURITY ALERT!")
        print("Untrusted server certificate!")
        print("Connection rejected.")
        print("Reason:", error)

    except (OSError, ssl.SSLError) as error:
        print("Connection error:", error)


print("=== ROBOT MITM SECURITY SIMULATION ===")

# TEST 1: Insecure client
insecure_context = ssl._create_unverified_context()

test_robot_connection(
    "INSECURE",
    insecure_context
)

# TEST 2: Secure client
secure_context = ssl.create_default_context(
    cafile=TRUSTED_CERT
)

test_robot_connection(
    "SECURE",
    secure_context
)

print("\n=== SIMULATION COMPLETE ===")
