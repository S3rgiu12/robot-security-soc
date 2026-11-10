
import socket

from robot_message_validator import validate_message
from robot_anomaly_detector import analyze_robot

HOST = "127.0.0.1"
PORT = 9001

print("=== ROBOT SECURE MONITORING SERVER ===")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Listening on {HOST}:{PORT}")

    while True:
        connection, address = server.accept()

        with connection:
            connection.settimeout(5)
            print(f"\nConnected: {address}")

            try:
                raw_data = connection.recv(1024)

                if not raw_data:
                    print("Empty connection")
                    continue

                message = raw_data.decode("utf-8")
                result = validate_message(message)

                if result is None:
                    response = "REJECTED: Invalid message"
                else:
                    robot_id, battery, temperature = result

                    analyze_robot(robot_id, battery, temperature)
                    response = "Telemetry analyzed"

                connection.sendall(response.encode("utf-8"))

            except (UnicodeDecodeError, socket.timeout) as error:
                print("Connection error:", error)

import socket

from robot_message_validator import validate_message
from robot_anomaly_detector import analyze_robot

HOST = "127.0.0.1"
PORT = 9001

print("=== ROBOT SECURE MONITORING SERVER ===")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Listening on {HOST}:{PORT}")

    while True:
        connection, address = server.accept()

        with connection:
            connection.settimeout(5)
            print(f"\nConnected: {address}")

            try:
                raw_data = connection.recv(1024)

                if not raw_data:
                    print("Empty connection")
                    continue

                message = raw_data.decode("utf-8")
                result = validate_message(message)

                if result is None:
                    response = "REJECTED: Invalid message"
                else:
                    robot_id, battery, temperature = result

                    analyze_robot(robot_id, battery, temperature)
                    response = "Telemetry analyzed"

                connection.sendall(response.encode("utf-8"))

            except (UnicodeDecodeError, socket.timeout) as error:
                print("Connection error:", error)
