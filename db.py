import sqlite3
from pathlib import Path

DB_FILE = Path("Logs/events.db")

def init_db() -> None:
    DB_FILE.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            username TEXT,
            password TEXT,
            command TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_event(event: dict) -> None:
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """
        INSERT INTO events
            (timestamp, event_type, src_ip, src_port, dst_port, username, password, command)
        VALUES
            (:timestamp, :event_type, :src_ip, :src_port, :dst_port, :username, :password, :command)
        """,
        {
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "username": event.get("username"),
            "password": event.get("password"),
            "command": event.get("command"),
        },
    )
    conn.commit()
    conn.close()
