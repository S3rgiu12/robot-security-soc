
# Day 04 - Lab 05
# Robot Anomaly Detector v2

ALLOWED_ROBOTS = {"R001", "R002"}


def analyze_robot(robot_id, battery, temperature):
    alerts = []
    status = "NORMAL"

    # Check robot identity
    if robot_id not in ALLOWED_ROBOTS:
        alerts.append("Unknown robot ID")
        status = "CRITICAL"

    # Check battery
    if not 0 <= battery <= 100:
        alerts.append("Invalid battery value")
        status = "CRITICAL"
    elif battery < 10:
        alerts.append("Battery critically low")
        status = "CRITICAL"
    elif battery < 20:
        alerts.append("Battery low")
        if status != "CRITICAL":
            status = "WARNING"

    # Check temperature
    if not -20 <= temperature <= 150:
        alerts.append("Invalid temperature value")
        status = "CRITICAL"
    elif temperature >= 90:
        alerts.append("Robot overheating")
        status = "CRITICAL"
    elif temperature >= 70:
        alerts.append("High temperature")
        if status != "CRITICAL":
            status = "WARNING"

    # Display results
    print("\n=== ROBOT SECURITY ANALYSIS ===")
    print("Robot:", robot_id)
    print("Battery:", battery)
    print("Temperature:", temperature)
    print("STATUS:", status)

    for alert in alerts:
        print("ALERT:", alert)

    return status, alerts


if __name__ == "__main__":
    analyze_robot("R001", 85, 42)
    analyze_robot("R001", 70, 95)
    analyze_robot("R002", 8, 45)
    analyze_robot("R999", 80, 40)
    analyze_robot("R001", 120, 200)
