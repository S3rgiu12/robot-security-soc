
import os
import stat
import pwd
import grp

FILE_PATH = "/tmp/robot-security-lab/config.txt"

EXPECTED_OWNER = "robot_guest"
EXPECTED_PERMISSIONS = 0o600

print("=== ROBOT FILE SECURITY AUDITOR ===")

# 1. Citim metadatele fisierului
file_info = os.stat(FILE_PATH)

# 2. Identificam proprietarul si grupul
owner = pwd.getpwuid(file_info.st_uid).pw_name
group = grp.getgrgid(file_info.st_gid).gr_name

# 3. Extragem permisiunile
permissions = stat.S_IMODE(file_info.st_mode)

print("\nFile:", FILE_PATH)
print("Owner:", owner)
print("Group:", group)
print("Permissions:", oct(permissions))

# 4. Verificam configuratia
if owner != EXPECTED_OWNER:
    print("WARNING: Unexpected file owner!")
else:
    print("Owner: OK")

if permissions != EXPECTED_PERMISSIONS:
    print("WARNING: Unexpected permissions!")
else:
    print("Permissions: OK")

# 5. Rezultatul auditului
if owner == EXPECTED_OWNER and permissions == EXPECTED_PERMISSIONS:
    print("\nSECURITY AUDIT: PASSED")
else:
    print("\nSECURITY AUDIT: REVIEW REQUIRED")
