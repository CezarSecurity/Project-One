import sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime

DB_FILE = Path("logs/events.db")

def get_login_attempts():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT src_ip, dst_port, timestamp, username, password FROM events "
        "WHERE event_type = 'login_attempt' ORDER BY timestamp"
    ).fetchall()
    conn.close()
    return rows

def get_commands():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT src_ip, timestamp, username, command FROM events "
        "WHERE event_type = 'command' ORDER BY timestamp"
    ).fetchall()
    conn.close()
    return rows

def detect_brute_force(rows, threshold=5, window_seconds=60):
    attempts_by_key = defaultdict(list)
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        key = (row["src_ip"], row["dst_port"])
        attempts_by_key[key].append(ts)

    alerts = []
    for (ip, port), timestamps in attempts_by_key.items():
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
                    "dst_port": port,
                    "attempt_count": threshold,
                    "window_seconds": round(gap, 2),
                    "first_attempt": window_start.isoformat(),
                })
                break
    return alerts

def detect_recon(rows):
    recon_commands = {"whoami", "uname -a", "id", "ps aux"}
    seen = defaultdict(set)
    for row in rows:
        if row["command"] in recon_commands:
            seen[row["src_ip"]].add(row["command"])

    alerts = []
    for ip, commands_used in seen.items():
        if len(commands_used) >= 2:
            alerts.append({
                "technique": "T1082",
                "technique_name": "System Information Discovery",
                "src_ip": ip,
                "commands": sorted(commands_used),
            })
    return alerts

def detect_credential_access(rows):
    alerts = []
    seen_ips = set()
    for row in rows:
        if row["command"] == "cat /etc/passwd" and row["src_ip"] not in seen_ips:
            seen_ips.add(row["src_ip"])
            alerts.append({
                "technique": "T1552.001",
                "technique_name": "Unsecured Credentials: Credentials In Files",
                "src_ip": row["src_ip"],
                "timestamp": row["timestamp"],
            })
    return alerts

def main():
    login_rows = get_login_attempts()
    command_rows = get_commands()

    alerts = []
    alerts += detect_brute_force(login_rows)
    alerts += detect_recon(command_rows)
    alerts += detect_credential_access(command_rows)

    if not alerts:
        print("No suspicious patterns detected.")
        return

    for alert in alerts:
        print(f"[{alert['technique']} {alert['technique_name']}] {alert['src_ip']}: {alert}")

if __name__ == "__main__":
    main()
