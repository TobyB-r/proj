import asyncio
import reciever


# this program sends messages, reciever.py recieves them.

friend = input("Enter IP: ")

async def start_client():
    while True:
        _, writer = await asyncio.open_connection(friend, port=reciever.port)

        message = input("Send message: ").encode()
        writer.write(message)
        
        await writer.drain()

asyncio.run(start_client())