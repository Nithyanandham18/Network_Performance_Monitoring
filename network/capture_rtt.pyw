import socket
import time
import csv

TARGET_HOST = "8.8.8.8"
TARGET_PORT = 53          # DNS port (always open)
INTERVAL = 0.5
OUTPUT_FILE = "rtt_log.csv"

def measure_rtt(host, port):
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, port))
        end = time.time()
        sock.close()
        return (end - start) * 1000  # ms
    except:
        return None

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "rtt_ms"])

    start_time = time.time()

    while True:
        rtt = measure_rtt(TARGET_HOST, TARGET_PORT)
        now = time.time() - start_time

        if rtt is not None:
            writer.writerow([round(now, 2), round(rtt, 2)])
            f.flush()

        time.sleep(INTERVAL)
