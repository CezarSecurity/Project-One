import asyncio

HOST = "127.0.0.1"
PORT = 2222

async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"Connection from {peer}")
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

asyncio.run(main())