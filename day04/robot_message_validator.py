
# Day 04 - Lab 05
# Robot TCP Message Validator

def validate_message(message):
    print("\nReceived:", message)

    try:
        fields = message.split(";")

        if len(fields) != 3:
            raise ValueError("Invalid number of fields")

        data = {}

        for field in fields:
            key, value = field.split("=", 1)

            if key in data:
                raise ValueError("Duplicate field")

            data[key] = value

        required = {"ROBOT_ID", "BATTERY", "TEMP"}

        if set(data) != required:
            raise ValueError("Missing or unexpected fields")

        robot_id = data["ROBOT_ID"]
        battery = int(data["BATTERY"])
        temperature = int(data["TEMP"])

        if not robot_id:
            raise ValueError("Empty robot ID")

        print("STATUS: VALID FORMAT")
        print("Robot:", robot_id)
        print("Battery:", battery)
        print("Temperature:", temperature)

        return robot_id, battery, temperature

    except (ValueError, TypeError) as error:
        print("STATUS: INVALID MESSAGE")
        print("Reason:", error)
        return None


# Test messages
messages = [
    "ROBOT_ID=R001;BATTERY=85;TEMP=42",
    "ROBOT_ID=R001;BATTERY=85",
    "ROBOT_ID=R001;BATTERY=abc;TEMP=42",
    "ROBOT_ID=R001;BATTERY=85;TEMP=42;MODE=AUTO",
    "ROBOT_ID=R001;BATTERY=85;BATTERY=20"
]

if __name__ == "__main__":
    for message in messages:
        validate_message(message)
