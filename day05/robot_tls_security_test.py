
import socket
import ssl

HOST = "127.0.0.1"
PORT = 9443
CERT = "certs/server.crt"


def test_connection(mode, context, server_name):
    print(f"\n=== {mode} TLS CLIENT ===")

    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            with context.wrap_socket(
                sock, server_hostname=server_name
            ) as secure_sock:
                print("TLS connection established!")
                print("TLS version:", secure_sock.version())
                print("Cipher:", secure_sock.cipher()[0])
                print("Certificate verification:",
                      "DISABLED" if mode == "INSECURE" else "ENABLED")

    except ssl.SSLCertVerificationError as error:
        print("SECURITY: Certificate rejected!")
        print("Reason:", error)

    except (OSError, ssl.SSLError) as error:
        print("Connection error:", error)


# Test 1: Insecure client
insecure_context = ssl._create_unverified_context()

test_connection(
    "INSECURE",
    insecure_context,
    HOST
)


# Test 2: Secure client, correct identity
secure_context = ssl.create_default_context(
    cafile=CERT
)

test_connection(
    "SECURE",
    secure_context,
    HOST
)


# Test 3: Secure client, incorrect identity
test_connection(
    "SECURE - WRONG IP",
    secure_context,
    "127.0.0.2"
)
