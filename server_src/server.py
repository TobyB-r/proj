import asyncio
import json

port = 9001
connected = {}
unsent = {}

read_lock = asyncio.Lock()
read_queue = asyncio.Queue()

async def callback(reader, writer):
    text = await reader.readline()
    handshake = json.loads(text)
    identity = handshake["identity"]
    connected[identity] = (reader, writer)

    if identity in unsent:
        for message in unsent:
            writer.write(message)
            await writer.drain()

    read_queue.put_nowait(asyncio.create_task(reader.readline(), name=identity))

async def client_loop():
    pending = set()
    
    while True:
        while not read_queue.empty():
            pending.add(read_queue.get_nowait())
        
        if not pending:
            pending = {await read_queue.get()}
        
        done, pending = await asyncio.wait(pending,
            return_when=asyncio.FIRST_COMPLETED, timeout=0.5)

        if done:
            try:
                winner = list(done)[0]
                
                if winner.exception():
                    raise winner.exception()
                
                message = winner.result()

                if message != b"":
                    line = json.loads(message)
                    recipient = line["recipient"]

                    if recipient in connected:
                        _, writer = connected[recipient]
                        writer.write(message)
                        await writer.drain()
                    elif recipient in unsent:
                        unsent[recipient].append(message)
                    else:
                        unsent[recipient] = [message]

                    identity = winner.get_name()
                    pending.add(asyncio.create_task(connected[identity][0].readline(), name=identity))
            except ConnectionError:
                pass

async def main():
    async with await asyncio.start_server(callback, port=port) as server:
        tasks = [client_loop(), server.serve_forever()]
        await asyncio.gather(*tasks)

asyncio.run(main())
