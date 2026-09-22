import asyncio
import asyncssh

HOST = "127.0.0.1"
PORT = 2222

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
        print(f"Login attempt: {username} / {password}")
        return False

async def start_server():
    await asyncssh.create_server(
        HoneypotSSHServer,
        HOST,
        PORT,
        server_host_keys=["ssh_host_key"]
    )
    print(f"Fae SSH server listening on {HOST}:{PORT}")

async def main():
    await start_server()
    await asyncio.Event().wait()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nStopped")