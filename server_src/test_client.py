import asyncio
import json

ip = input("Enter IP:")
port = 9001
identity = "windows"
recipient = "linux"
msg = "I'm stuff :)"

async def main():
    reader, writer = await asyncio.open_connection(ip, port=port)

    # handshake
    handshake = json.dumps({"identity": identity})
    writer.write(handshake.encode("ascii"))
    # writer.write(b"\n")
    await writer.drain()

    # serialized = json.dumps({"sender": identity, "recipient": recipient, "message": msg})
    # print(serialized)

    while True:
        line = await reader.readline()
        
        if not line:
            break
        
        print(line)

asyncio.run(main())
