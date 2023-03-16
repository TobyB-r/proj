import asyncio
import json
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

# port used to communicate
port = 9001
# connected contains the clients that are currently connected
connected = {}
# unsent contains messages sent to clients that aren't connected
unsent = {}
# x3dh and otp_keys contain key bundles for connected users
x3dh = {}
otp_keys = {}

# called by the server when a client connects
async def callback(reader, writer):
    try:
        addr = writer.get_extra_info("peername")
        print("Connected to", addr)

        # information about the client the second they connect
        message = await reader.readline()

        # verifying this is the real user
        signature = (await reader.readline())[:-1]
        signature = b64decode(signature)
        handshake = json.loads(message.decode("ascii"))
        _x3dh = handshake["x3dh"]
        id_key = serialization.load_der_public_key(b64decode(_x3dh["id_key"]))
        id_key.verify(signature, message, ec.ECDSA(SHA256()))

        identity = handshake["identity"]
        connected[identity] = writer

        # saving x3dh keys
        otp_keys[identity] = _x3dh["otp_keys"]
        del _x3dh["otp_keys"]
        x3dh[identity] = _x3dh

        print("finished handshake")

        # unsent messages were sent before the client connected
        if identity in unsent:
            print(unsent[identity])
            for msg in unsent[identity]:
                message, ciphertext = msg
                print("writing unsent", message)
                writer.write(message + ciphertext)
                await writer.drain()
            
            del unsent[identity]
        
        print("Connected to", identity)

        while True:
            message = await reader.readline()
            
            # the reader disconnected
            if message == b"":
                print(identity, "disconnected")
                del connected[identity]
                return
            
            # verifying the message
            signature = (await reader.readline())[:-1]
            signature = b64decode(signature)
            id_key.verify(signature, message, ec.ECDSA(SHA256()))
            print("received", message)    
            
            line = json.loads(message.decode("ascii"))
            
            # this is request for x3dh keys
            if "request" in line:
                if line["request"] in x3dh:
                    x = x3dh[line["request"]]
                    x["identity"] = line["request"]

                    # if there are any keys left for this user add one
                    if otp_keys[line["request"]]:
                        x["otp_key"] = otp_keys[line["request"]].pop()
                        x["otp_ind"] = len(otp_keys[line["request"]])
                    
                    response = json.dumps(x).encode("ascii") + b"\n"
                    writer.write(response)
                    await writer.drain()
                    print("sent", response)
                else:
                    # we don't have keys for this user
                    # send a json empty dictionary
                    writer.write(b"{}\n")
                    await writer.drain()
                    print("sent {}")
                
                continue

            recipient = line["recipient"]
            ciphertext = await reader.readexactly(line["length"])
            
            # send the message if we are connected
            # save it to unsent if we aren't
            if recipient in connected:
                x_writer = connected[recipient]

                x_writer.write(message + ciphertext)
                await x_writer.drain()

                print("sent", message)
            elif recipient in unsent:
                unsent[recipient].append((message, ciphertext))
            else:
                unsent[recipient] = [(message, ciphertext)]
    except Exception as e:
        print(e)
        writer.close()
        await writer.wait_closed()

async def main():
    async with await asyncio.start_server(callback, port=port) as server:
        # async with task_group:
        #     task_group.create_task(server.serve_forever())
        await server.serve_forever()

asyncio.run(main())