import psutil
import time
import csv

OUTPUT_FILE = "network_log.csv"

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "sent_rate", "recv_rate"])

    print("Collecting data... Press Ctrl+C to stop")

    start = time.time()

    prev = psutil.net_io_counters()
    prev_sent = prev.bytes_sent
    prev_recv = prev.bytes_recv

    while True:
        time.sleep(1)

        current = psutil.net_io_counters()
        curr_sent = current.bytes_sent
        curr_recv = current.bytes_recv

        # Calculate per-second rate
        sent_rate = curr_sent - prev_sent
        recv_rate = curr_recv - prev_recv

        timestamp = round(time.time() - start, 2)

        writer.writerow([timestamp, sent_rate, recv_rate])
        f.flush()

        prev_sent = curr_sent
        prev_recv = curr_recv