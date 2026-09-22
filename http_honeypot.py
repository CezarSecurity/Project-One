import asyncio
from datetime import datetime, timezone
from aiohttp import web

from db import init_db, insert_event
from ssh_honeypot import log_event

HOST = "127.0.0.1"
PORT = 8080

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>TP-Link Archer C7 - Login</title></head>
<body>
<h2>TP-Link Archer C7</h2>
<form method="POST" action="/login">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
</body>
</html>
"""

INVALID_PAGE = "<html><body><h3>Invalid username or password.</h3></body></html>"

async def handle_get(request: web.Request) -> web.Response:
    return web.Response(text=LOGIN_PAGE, content_type="text/html")

async def handle_login(request: web.Request) -> web.Response:
    data = await request.post()
    username = data.get("username", "")
    password = data.get("password", "")
    peer = request.transport.get_extra_info("peername")
    src_ip, src_port = peer[0], peer[1]

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "login_attempt",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": PORT,
        "username": username,
        "password": password,
    }
    log_event(event)
    insert_event(event)
    print(f"HTTP login attempt: {username} / {password} from {src_ip}")

    return web.Response(text=INVALID_PAGE, content_type="text/html", status=401)

def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_get)
    app.router.add_post("/login", handle_login)
    return app

async def main():
    init_db()
    app = build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, PORT)
    await site.start()
    print(f"Fake HTTP router login listening on {HOST}:{PORT}")
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped")
