import asyncio
import json

ip = input("Enter IP:")
identity = "unit1"
recipient = "unit2"
msg = "I'm stuff :)"

async def main():
    reader, writer = await asyncio.open_connection(ip)

    serialized = json.dumps({"sender": identity, "recipient": recipient, "message": msg})
    print(serialized)

    writer.write(serialized)
    writer.write("\n")

asyncio.run(main())