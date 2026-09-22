import asyncio
import asyncssh
from datetime import datetime, timezone
from storage import log_event, init_db, insert_event

HOST = "127.0.0.1"
PORT = 2222

async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    peer = process.get_extra_info("peername")
    username = process.get_extra_info("username")
    process.stdout.write("Welcome to Ubuntu 22.04.3 LTS\r\n")
    try:
        while True:
            process.stdout.write("$ ")
            try:
                line = await asyncio.wait_for(process.stdin.readline(), timeout=120)
            except asyncio.TimeoutError:
                process.stdout.write("\r\nIdle timeout. \r\n")
                break

            if not line:
                break
            command = line.rstrip("\r\n")

            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "command",
                "src_ip": peer[0],
                "src_port": peer[1],
                "dst_port": PORT,
                "username": username,
                "command": command,
            }
            insert_event(event)

            if command in ("exit", "logout"):
                break
            elif command == "whoami":
                process.stdout.write("root\r\n")
            elif command == "pwd":
                process.stdout.write("/root\r\n")
            elif command == "id":
                process.stdout.write("uid=0(root) gid=0(root) groups=0(root)\r\n")
            elif command == "uname -a":
                process.stdout.write(
                    "Linux ubuntu 5.25.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
                )
            elif command == "ls":
                process.stdout.write("snap  Documents  Downloads\r\n")
            elif command == "cat /etc/passwd":
                process.stdout.write(
                    "root:x:0:0:root:/root:/bin/bash\r\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                    "admin:x:1000:1000:admin:/home/admin:/bin/bash\r\n"
                )
            elif command == "sudo su":
                process.stdout.write("root\r\n")
            elif command.startswith("wget ") or command.startswith("curl "):
                process.stdout.write(
                    f"bash: {command.split()[0]}: command not found\r\n"
                )
            elif command == "ps aux":
                process.stdout.write(
                    "USER  PID %CPU %MEM COMMAND\r\n"
                    "root    1  0.0  0.1 /sbin/init\r\n"
                    "root   89  0.0  0.2 /usr/sbin/sshd\r\n"        
                )
            elif command == "history":
                process.stdout.write("\r\n")
            else:
                process.stdout.write(f"bash: {command}: command not found\r\n")
    except asyncssh.BreakReceived:
        pass
    process.exit(0)

class HoneypotSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn
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
        insert_event(event)
        print(f"Login attempt: {username} / {password}")
        return True

async def start_server():
    await asyncssh.create_server(
        HoneypotSSHServer,
        HOST,
        PORT,
        server_host_keys=["ssh_host_key"],
        process_factory=handle_session
    )
    print(f"Fake SSH server listening on {HOST}:{PORT}")

async def main():
    init_db()
    await start_server()
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped")