
import socket
import time

HOST = "127.0.0.1"
PORT = 9001

test_messages = [
    ("NORMAL", "ROBOT_ID=R001;BATTERY=85;TEMP=42"),
    ("OVERHEATING", "ROBOT_ID=R001;BATTERY=70;TEMP=95"),
    ("LOW BATTERY", "ROBOT_ID=R002;BATTERY=8;TEMP=45"),
    ("UNKNOWN ROBOT", "ROBOT_ID=R999;BATTERY=80;TEMP=40"),
    ("INVALID MESSAGE", "ROBOT_ID=R001;BATTERY=abc;TEMP=42")
]

print("=== ROBOT SECURITY TEST CLIENT ===")

for test_name, message in test_messages:
    print(f"\n[TEST] {test_name}")

    try:
        with socket.create_connection(
            (HOST, PORT), timeout=5
        ) as client:

            client.settimeout(5)
            client.sendall(message.encode("utf-8"))

            response = client.recv(1024).decode("utf-8")

            print("Sent:", message)
            print("Server response:", response)

    except (OSError, UnicodeError) as error:
        print("Connection error:", error)

    time.sleep(1)

print("\n=== ALL TESTS FINISHED ===")
