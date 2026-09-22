import sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime

DB_FILE = Path("Logs/events.db")

def get_login_attempts():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT src_ip, timestamp, username, password FROM events "
        "WHERE event_type = 'login_attempt' ORDER BY timestamp"
    ).fetchall()
    conn.close()
    return rows

def detect_brute_force(rows, threshold=5, window_seconds=60):
    attempts_by_ip = defaultdict(list)
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        attempts_by_ip[row["src_ip"]].append(ts)

    alerts = []
    for ip, timestamps in attempts_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - threshold + 1):
            window_start = timestamps[i]
            window_end = timestamps[i + threshold - 1]
            gap = (window_end - window_start).total_seconds()
            if gap <= window_seconds:
                alerts.append({
                    "technique": "T1110",
                    "technique_name": "Brute Force",
                    "src_ip": ip,
                    "attempt_count": threshold,
                    "window_seconds": round(gap, 2),
                    "first_attempt": window_start.isoformat(),
                })
                break
    return alerts

def main():
    rows = get_login_attempts()
    alerts = detect_brute_force(rows)
    if not alerts:
        print("No brute force patterns detected")
    for alert in alerts:
        print(
            f"[{alert['technique']} {alert['technique_name']}] "
            f"{alert['src_ip']}: {alert['attempt_count']} attempts "
            f"in {alert['window_seconds']}s (starting {alert['first_attempt']})"
        )
if __name__ == "__main__":
    main()
