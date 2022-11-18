import asyncio
import json

port = 9001
# connected contains the clients that are currently connected
connected = {}
# unsent contains messages sent to clients that aren't connected
unsent = {}

# when clients connect they are added to the read queue
read_queue = asyncio.Queue()

# called by the server when a client connects
async def callback(reader, writer):
    print("Connected to", writer.get_extra_info("peername"))

    # information about the client the second they connect
    text = await reader.readline()
    handshake = json.loads(text)
    identity = handshake["identity"]
    connected[identity] = (reader, writer)
    print("Connected to", identity)

    # unsent messages were sent before the client connected
    if identity in unsent:
        for message in unsent[identity]:
            msg = message.encode("ascii")
            print("writing", msg)
            writer.write(msg)
        
        await writer.drain()
        del unsent[identity]

    read_queue.put_nowait(asyncio.create_task(reader.readline(),
        name=identity))

async def client_loop():
    # wait for a client to connect
    pending = {asyncio.create_task(read_queue.get())}
    
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
        # if it was the read queue the name is read_queue.get
        completed = list(done)[0]
        identity = completed.get_name()

        try:
            # get the single task in done
            # the task raised an exception
            exception = completed.exception()
            
            if exception is not None:
                raise exception

            result = completed.result()

            if type(result) is asyncio.Task:
                # add the new task and wait for the next item in the queue
                pending.add(result)
                pending.add(asyncio.create_task(read_queue.get()))
                continue

            if result == b"":
                del connected[identity]
                continue
        
            line = json.loads(result)
            recipient = line["recipient"]
            print("Recieved message from", identity, "to", recipient)

            if recipient in connected:
                _, writer = connected[recipient]
                writer.write(result)
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
            pass

async def main():
    async with await asyncio.start_server(callback, port=port) as server:
        tasks = [client_loop(), server.serve_forever()]
        await asyncio.gather(*tasks)

asyncio.run(main())
