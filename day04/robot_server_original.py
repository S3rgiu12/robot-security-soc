
import socket

HOST = "127.0.0.1"
PORT = 9000

print("=== ROBOT TCP SERVER v2 ===")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Server listening on {HOST}:{PORT}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            print("\nWaiting for robot connection...")

            conn, addr = server.accept()

            with conn:
                conn.settimeout(5)
                print("Connected by:", addr)

                try:
                    data = conn.recv(1024)

                    if data:
                        message = data.decode("utf-8")
                        print("Robot telemetry:", message)

                        conn.sendall(b"Telemetry received")
                    else:
                        print("Client disconnected without data.")

                except (OSError, UnicodeError) as error:
                    print("Communication error:", error)

    except KeyboardInterrupt:
        print("\nServer stopped safely.")

