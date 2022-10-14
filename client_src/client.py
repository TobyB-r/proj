import asyncio
from tkinter import Tk, StringVar
import json

# client class updates the ui and controls networking
# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop and using asyncio.sleep() lets asyncio run between updates
class Client(Tk):
    def __init__(self, ip, port, identity):
        super().__init__()
        self.ip = ip
        self.port = port
        self.identity = identity
        self.nextmsg = StringVar(self)
        self.msg_queue = asyncio.Queue()
        self.history_lock = asyncio.Lock()

    # begin the program
    async def start_loop(self):
        self.reader, self.writer = await asyncio.open_connection(self.ip, port=self.port)
        
        handshake = json.dumps({"identity": self.identity})
        self.writer.write(handshake.encode("ascii"))
        self.writer.write(b"\n")
        await self.writer.drain()

        # coroutines that happen continuously in the background
        # self.msg_client() sends messages when they enter msg_queue
        # self.listen() periodically checks if a message has been recieved by self.reader
        # self.updater() handles the UI like Tk.mainloop() would
        coro = [self.updater(), self.listen(), self.msg_client()]
        await asyncio.gather(*coro)
    
    # waits for messages in the queue then sends them
    async def msg_client(self):
        while True:
            # msg_queue.get() will wait until an item is added to the queue
            msg = await self.msg_queue.get()
            text = json.dumps(msg)
            self.writer.write(text.encode("ascii"))
            self.writer.write(b"\n")
            await self.writer.drain()
            
            # history is a Tk Text widget that shows messages for the user
            async with self.history_lock:
                self.history.configure(state="normal")
                self.history.insert( "end", "\nYou sent: " + msg["message"])
                self.history.configure(state="disabled")
    
    # periodically checks if a message has been recieved
    async def listen(self):
        while True:
            msg = await self.reader.readline()

            if msg:
                obj = json.loads(msg)

                async with self.history_lock:
                    self.history.configure(state="normal")
                    self.history.insert("ende", "\n" + obj["sender"] + " sent " + obj["message"])
                    self.history.configure(state="disabled")

    # replacement for Tk.mainloop()
    async def updater(self):
        # sets a flag that Tk.mainloop() usually does, prevents some bugs
        self.willdispatch()

        while True:
            # runs all events to do with tkinter and user input
            # asyncio.sleep() lets io happen in background
            self.update()
            await asyncio.sleep(0.05)

    # method used by the send button, has to be synchronous
    # send message is async so it adds item to the msg_queue
    def send_msg(self):
        self.msg_queue.put_nowait({
            "sender": self.identity,
            "message": self.nextmsg.get(),
            "recipient": "linux",
        })
