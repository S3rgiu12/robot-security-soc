import subprocess
import platform
import getpass
import shutil
from datetime import datetime

print("=== SECURITY DIAGNOSTICS v1 ===")

# 1. Informatii despre sistem
print("\n[1] SYSTEM INFORMATION")
print("OS:", platform.system())
print("Kernel:", platform.release())
print("Architecture:", platform.machine())

# 2. Utilizatorul curent
print("\n[2] USER INFORMATION")
print("Current user:", getpass.getuser())

# 3. Verificarea spatiului pe disc
print("\n[3] DISK DIAGNOSTICS")

total, used, free = shutil.disk_usage("/")

free_percent = (free / total) * 100

print(f"Total space: {total / (1024**3):.2f} GB")
print(f"Free space: {free / (1024**3):.2f} GB")
print(f"Free percentage: {free_percent:.2f}%")

if free_percent < 15:
    print("WARNING: LOW DISK SPACE!")
else:
    print("STATUS: Disk space OK")

# 4. Data si ora verificarii
print("\n[4] DIAGNOSTIC TIME")
print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# 5. Monitorizarea proceselor active
print("\n[5] PROCESS MONITORING")

result = subprocess.run(
    ["ps", "-eo", "pid,comm"],
    capture_output=True,
    text=True,
    check=True
)

processes = result.stdout.splitlines()

print("Total processes:", len(processes) - 1)
print("\nFirst 10 processes:")

for process in processes[1:11]:
    print(process)

print("\n=== DIAGNOSTICS COMPLETE ===")
