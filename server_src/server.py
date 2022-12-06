from cryptography.hazmat.primitives import hashes, hashes, kdf, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

import asyncio
import json
import base64

# port used to communicate
port = 9001
# connected contains the clients that are currently connected
connected = {}
# keys contains public keys that the users use for e2e encryption
keys = {}
# unsent contains messages sent to clients that aren't connected
unsent = {}
# when clients connect they are added to the read queue
read_queue = asyncio.Queue()

def derive_key(private, public):
    shared_key = private.exchange(ec.ECDH(), public)

    return base64.urlsafe_b64encode(HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake-derivation"
    ).derive(shared_key))

# called by the server when a client connects
async def callback(reader, writer):
    print("Connected to", writer.get_extra_info("peername"))
    
    peer_key = await reader.read(120)
    peer_key = serialization.load_der_public_key(peer_key)
    
    private_key = ec.generate_private_key(ec.SECP384R1)    
    fernet = Fernet(derive_key(private_key, peer_key))
    
    public_key = private_key.public_key()
    
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    writer.write(serialized_public)
    await writer.drain()

    # information about the client the second they connect
    handshake = await reader.readline()
    handshake = json.loads(fernet.decrypt(handshake).decode("ascii"))

    identity = handshake["identity"]

    connected[identity] = (reader, writer, fernet)    

    # unsent messages were sent before the client connected
    if identity in unsent:
        for message in unsent[identity]:
            print("writing unsent", message)
            encrypted = fernet.encrypt(message)
            writer.write(encrypted)
            writer.write(b"\n")
            await writer.drain()
        
        del unsent[identity]

    read_queue.put_nowait(asyncio.create_task(reader.readline(),name=identity))
    
    print("Connected to", identity)

async def client_loop():
    # wait for a client to connect
    pending = {asyncio.create_task(read_queue.get(), name="readqueue")}
    
    
    while True:
        # wait for any of the readers to respond
        # or for something to be added to the readqueue
        # done has the task that finished pending contains the rest
        # tasks in pending are reused instead of constructing them again
        done, pending = await asyncio.wait(pending,
            return_when=asyncio.FIRST_COMPLETED)

        if not done:
            continue
        
        # identity is the name of the completed task
        # if a reader finished first the name is the key in connected
        completed = list(done)[0]
        identity = completed.get_name()

        try:
            # get the single task in done
            # the task raised an exception
            exception = completed.exception()
            
            if exception is not None:
                raise exception

            result = completed.result()

            # the task that finished was read_queue.get
            if type(result) is asyncio.Task:
                # add the new task and wait for the next item in the queue
                pending.add(result)
                pending.add(asyncio.create_task(read_queue.get()))
                continue
            
            # the task was the end of a reader
            if result == b"":
                del connected[identity]
                continue

            fernet = connected[identity][2]
            result = fernet.decrypt(result[:-1])
            line = json.loads(result)
            recipient = line["recipient"]
            print("Recieved result from", identity, "to", recipient)

            # send the message if we are connected
            # save it to unsent if we aren't
            if recipient in connected:
                _, writer, fernet = connected[recipient]
                encrypted = fernet.encrypt(result)
                writer.write(encrypted)
                writer.write(b"\n")
                await writer.drain()
                print("sent", result)
            elif recipient in unsent:
                unsent[recipient].append(result)
                print("didn't send", result)
            else:
                unsent[recipient] = [result]
                print("didn't send", result)

            # if everything else completed successfully add it back to pending
            # the program won't get to this line if the task threw exception
            pending.add(asyncio.create_task(connected[identity][0].readline(), name=identity))
        except ConnectionError:
            del connected[identity]
            print(identity, "disconnected")
            pass

async def main():
    async with await asyncio.start_server(callback, port=port) as server:
        tasks = [client_loop(), server.serve_forever()]
        await asyncio.gather(*tasks)

asyncio.run(main())

