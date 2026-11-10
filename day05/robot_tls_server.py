
import socket
import ssl

HOST = "127.0.0.1"
PORT = 9443

CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"


def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Folosim minimum TLS 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Incarcam certificatul si cheia privata
    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        print("=== ROBOT TLS SECURITY SERVER ===")
        print(f"Listening on {HOST}:{PORT}")
        print("Waiting for secure connections...")

        while True:
            client, address = server.accept()

            try:
                with context.wrap_socket(
                    client, server_side=True
                ) as secure_client:

                    print(f"\nConnected: {address}")
                    print(
                        "TLS version:",
                        secure_client.version()
                    )
                    print(
                        "Cipher:",
                        secure_client.cipher()
                    )

                    data = secure_client.recv(4096)

                    if not data:
                        continue

                    message = data.decode("utf-8")
                    print("Received telemetry:", message)

                    secure_client.sendall(
                        b"Telemetry received securely"
                    )

            except (ssl.SSLError, OSError, UnicodeError) as error:
                print("Connection error:", error)
                client.close()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nServer stopped.")
