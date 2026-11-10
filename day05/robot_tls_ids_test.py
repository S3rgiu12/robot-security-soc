
import socket
import ssl

from robot_security_logger import (
    log_connection,
    log_security_alert,
    log_success
)

HOST = "127.0.0.1"
PORT = 9555

MESSAGE = "ROBOT_ID=R001;BATTERY=85;TEMP=42"
CERT_FILE = "certs/server.crt"


def test_robot_connection(secure=True):
    mode = "SECURE" if secure else "INSECURE"

    print(f"\n=== {mode} ROBOT TEST ===")
    log_connection(HOST, PORT)

    if secure:
        context = ssl.create_default_context(
            cafile=CERT_FILE
        )
        context.check_hostname = True
    else:
        # Exclusiv pentru simularea din laborator!
        context = ssl._create_unverified_context()

    try:
        with socket.create_connection(
            (HOST, PORT), timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=HOST
            ) as tls_sock:

                print("TLS connection established!")

                tls_sock.sendall(MESSAGE.encode())
                response = tls_sock.recv(1024)

                print(
                    "Server response:",
                    response.decode(errors="replace")
                )

                if secure:
                    log_success(
                        "Verified TLS connection established"
                    )
                else:
                    log_security_alert(
                        "Telemetry sent without certificate "
                        "verification - MITM risk"
                    )

    except ssl.SSLCertVerificationError as error:
        print("SECURITY: Untrusted certificate rejected!")
        print("Reason:", error)

        log_security_alert(
            f"TLS certificate rejected: {error}"
        )

    except (OSError, ssl.SSLError) as error:
        print("Connection error:", error)

        log_security_alert(
            f"TLS connection error: {error}"
        )


if __name__ == "__main__":
    print("=== ROBOT TLS INTRUSION DETECTION TEST ===")

    test_robot_connection(secure=False)
    test_robot_connection(secure=True)

    print("\n=== TEST COMPLETE ===")
