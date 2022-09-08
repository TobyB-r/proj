import asyncio

# this program sends messages, reciever.py recieves them.

friend = input("Enter IP: ")

async def start_client(message):
    _, writer = await asyncio.open_connection(friend, 123)

    message = input("Send message: ").encode()
    writer.write(message)
    
    await writer.drain()

asyncio.run(start_client('Hello World!'))