import time

print("Safe keylogger-behaviour simulation is running.")
print("This file does not capture any keyboard input.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Simulation stopped.")