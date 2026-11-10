
import os
import stat

file_path = "robot_config.txt"

file_info = os.stat(file_path)

permissions = stat.S_IMODE(file_info.st_mode)

print("=== ROBOT SECURITY CHECK ===")
print("File:", file_path)
print("Permissions:", oct(permissions))

if permissions == 0o600:
    print("STATUS: Protected")
else:
    print("WARNING: Review file permissions")
