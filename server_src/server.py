import asyncio
import json

# demo for how the server will work
# when clients connect they give their identity
# if identity isn't already in the list it is added
# messages say what client they are meant for
# if that client is online then the server relays the message
# otherwise the messages is stored for when the client comes back
# communication over network is serialized

port = 9001

unsent = {}
connected = {}

async def callback(reader, writer):
    handshake = json.loads(await reader.readline())
    identity = handshake["identity"]
    connected[identity] = (reader, writer)
    
    # if identity not in unsent:
    #     unsent[identity] = []
    # elif len(unsent[identity]):
    #     for msg in unsent[identity]:
    #         writer.write(msg)
    #         writer.write(b"\n")
    #         await writer.drain()

    try:
        while True:
            line = json.loads(await reader.readline())
            recipient = line["recipient"]

            if recipient in connected:
                reader, writer = recipient[connected]
                writer.write(line)
                writer.write(b"\n")
            # elif recipient in unsent:
            #     unsent[recipient].append(line)
            # else:
            #     unsent[recipient] = [line]
    except ConnectionError:
        del connected[identity]
        # del unsent[identity]

async def main():
    async with asyncio.start_server(callback, port=port) as server:
        server.serve_forever()

asyncio.run(main())
