import asyncio
import asyncssh
import json
from datetime import datetime, timezone
from pathlib import Path

HOST = "127.0.0.1"
PORT = 2222
LOG_FILE = Path("logs/events.json1")

def log_event(event : dict) -> None:
    LOG_FILE.parent.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

class HoneypotSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        print(f"SSH connection from {peer}")

    def begin_auth(self, username):
        print(f"Client trying to authenticate as: {username}")
        return True
    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        peer = self._conn.get_extra_info("peername")
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "login_attempt",
            "src_ip": peer[0],
            "src_port": peer[1],
            "dst_port": PORT,
            "username": username,
            "password": password,
        }
        log_event(event)
        print(f"Login attempt: {username} / {password}")
        return False

async def start_server():
    await asyncssh.create_server(
        HoneypotSSHServer,
        HOST,
        PORT,
        server_host_keys=["ssh_host_key"]
    )
    print(f"Fake SSH server listening on {HOST}:{PORT}")

async def main():
    await start_server()
    await asyncio.Event().wait()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nStopped")