
import socket
import ssl

HOST = "127.0.0.1"
PORT = 9555

CERT = "certs/fake_server/fake.crt"
KEY = "certs/fake_server/fake.key"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(certfile=CERT, keyfile=KEY)

print("=== FAKE ROBOT TLS SERVER ===", flush=True)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Listening on {HOST}:{PORT}", flush=True)

    while True:
        client, address = server.accept()
        print(f"\nConnection from: {address}", flush=True)

        try:
            with context.wrap_socket(
                client, server_side=True
            ) as tls_client:
                print("TLS handshake successful!")
                print("Protocol:", tls_client.version())

                tls_client.settimeout(3)
                data = tls_client.recv(4096)

                if data:
                    print("Received:", data.decode(
                        "utf-8", errors="replace"
                    ))
                    tls_client.sendall(
                        b"Fake server response"
                    )

        except (ssl.SSLError, OSError) as error:
            print("Connection failed:", error)
