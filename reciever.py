import asyncio

port = 9001

# this program recieves messages, main.py sends them

async def handle(reader, writer):
    data = await reader.read()
    message = data.decode()
    sender = writer.get_extra_info("peername")
    print(message)
    print(sender)

async def serve():
    async with await asyncio.start_server(handle, port=9001) as server:
        print("listening on port {}".format(port))
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())