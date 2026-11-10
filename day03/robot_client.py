
import socket

HOST = "127.0.0.1"
PORT = 9000

robot_id = "R001"
battery = 85
temperature = 42

message = (
    f"ROBOT_ID={robot_id};"
    f"BATTERY={battery};"
    f"TEMP={temperature}"
)

print("=== ROBOT TCP CLIENT ===")
print("Connecting to server...")

try:
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        print("Connected successfully!")

        client.sendall(message.encode("utf-8"))
        print("Telemetry sent:", message)

        response = client.recv(1024)
        print("Server response:", response.decode("utf-8"))

except OSError as error:
    print("Connection error:", error)

print("=== CLIENT FINISHED ===")

import socket

HOST = "127.0.0.1"
PORT = 9000

robot_id = "R001"
battery = 85
temperature = 42

message = (
    f"ROBOT_ID={robot_id};"
    f"BATTERY={battery};"
    f"TEMP={temperature}"
)

print("=== ROBOT TCP CLIENT ===")
print("Connecting to server...")

try:
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        print("Connected successfully!")

        client.sendall(message.encode("utf-8"))
        print("Telemetry sent:", message)

        response = client.recv(1024)
        print("Server response:", response.decode("utf-8"))

except OSError as error:
    print("Connection error:", error)

print("=== CLIENT FINISHED ===")
