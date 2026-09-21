import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

HOST = "127.0.0.1"
PORT = 2222
LOG_FILE = Path("logs/events.json1")

def log_event(event : dict):
    LOG_FILE.parent.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

async def handle_client(reader, writer):
    src_ip, src_port = writer.get_extra_info("peername")[:2]
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "connection",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": PORT,
    }
    log_event(event)
    print(f"logged connection from {src_ip}:{src_port}")
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nStopped")