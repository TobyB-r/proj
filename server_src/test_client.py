import asyncio
import json

ip = input("Enter IP:")
identity = "jimmy"
recipient = "bob"
msg = "I'm stuff :)"

async def main():
    reader, writer = await asyncio.open_connection(ip)

    serialized = json.dumps({"sender": identity, "recipient": recipient, "message": msg})
    print(serialized)

    writer.write(serialized)
    writer.write("\n")

asyncio.run(main())
