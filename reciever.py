import asyncio

# this program recieves messages, main.py sends them

async def handle(reader, writer):
    data = await reader.read(100)
    message = data.decode()
    sender = writer.get_extra_info("peername")
    print(message)
    print(sender)

async def main():
    async with await asyncio.start_server(handle, port=9001) as server:
        await server.serve_forever()

asyncio.run(main())