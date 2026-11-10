
import socket
import ssl

HOST = "127.0.0.1"
PORT = 9443

MESSAGE = "ROBOT_ID=R001;BATTERY=85;TEMP=42"

print("=== ROBOT TLS CLIENT ===")

# Create a TLS context and trust our lab certificate
context = ssl.create_default_context(
    cafile="certs/server.crt"
)

# Require TLS 1.3
context.minimum_version = ssl.TLSVersion.TLSv1_3

try:
    # Create the TCP connection
    with socket.create_connection((HOST, PORT), timeout=5) as sock:

        # Upgrade TCP connection to TLS
        with context.wrap_socket(
            sock,
            server_hostname=HOST
        ) as secure_sock:

            print("TLS connection established!")
            print("TLS version:", secure_sock.version())
            print("Cipher:", secure_sock.cipher()[0])

            secure_sock.sendall(MESSAGE.encode())
            print("Telemetry sent:", MESSAGE)

            response = secure_sock.recv(1024)
            print("Server response:", response.decode())

except (OSError, ssl.SSLError) as error:
    print("Connection error:", error)

print("=== CLIENT FINISHED ===")
