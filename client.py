import asyncio
from tkinter import Tk, StringVar

# client class updates the ui and controls networking
# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop and using asyncio.sleep() lets asyncio run between updates
class Client(Tk):
    def __init__(self, ip, port) -> None:
        super().__init__()
        self.ip = ip
        self.port = port
        self.nextmsg = StringVar(self)
        self.peer = None
        self.reader = None
        self.msg_queue = None
        self.writer = None

    async def set_streams(self, reader, writer):
        print("Connected to server")
        self.reader = reader
        self.writer = writer
        self.peer, _ = self.writer.get_extra_info("peername")

        if self.server is not None:
            print("closing server")
            self.server.close()
            print("Server closed")

    # begin the program
    async def start_loop(self):
        # the queue is initiated here after asyncio.run() has been called
        # queues made in __init__ attach to another event loop and don't work
        self.msg_queue = asyncio.Queue()

        # if the user entered "listen" wait for another computer to connect
        # otherwise open a connection with the ip address that they entered
        if self.ip == "listen":
            # open a server that waits for another computer to connect
            # as soon as it recieves a message the callback cancels it
            try:
                async with await asyncio.start_server(
                    self.set_streams, port=self.port) as self.server:

                    print(f"listening on port {self.port}")
                    # serve_forever() serves until something calls server.close()
                    await self.server.serve_forever()
            # when the callback calls server.close() it makes a CancelledError
            except asyncio.exceptions.CancelledError:
                print("Found friend {}".format(self.writer.get_extra_info("peername")))
        else:
            self.reader, self.writer = await asyncio.open_connection(self.ip, port=self.port)
            self.peer, _ = self.writer.get_extra_info("peername")

        # tasks that happen continuously in the background
        # these are assigned to an array to prevent them being garbage collected
        # self.msg_client() sends messages when they enter msg_queue
        # self.listen() periodically checks if a message has been recieved by self.reader
        # self.updater() handles the UI like Tk.mainloop() would
        self.tasks = [self.updater(), self.listen(), self.msg_client()]
        
        # this waits for tasks that loop forever.
        await asyncio.gather(*self.tasks)
    
    # waits for messages in the queue then sends them
    async def msg_client(self):
        while True:
            # msg_queue.get() will wait until an item is added to the queue somewhere else
            # when an item is added to msg_queue it is sent and we start waiting again
            msg = await self.msg_queue.get()

            self.writer.write(msg.encode())
            await self.writer.drain()
            
            # history is a Tk Text widget that shows messages for the user
            self.history.configure(state="normal")
            self.history.insert( "end", "\nYou sent: " + msg)
            self.history.configure(state="disabled")
    
    # periodically checks if a message has been recieved
    async def listen(self):
        while True:
            msg = await self.reader.read(100)

            if msg:
                self.history.configure(state="normal")
                self.history.insert("end", "\n" + self.peer + " sent: " + msg.decode())
                self.history.configure(state="disabled")
            
            await asyncio.sleep(1)

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
        self.msg_queue.put_nowait(self.nextmsg.get())
