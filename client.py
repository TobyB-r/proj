import asyncio
from tkinter import *

# client class controls the ui and networking
# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop and using asyncio.sleep() lets asyncio run between updates
class Client(Tk):
    def __init__(self, ip, port) -> None:
        super().__init__()
        self.ip = ip
        self.port = port
        self.nextmsg = StringVar(self)
        self.peer = ""
        self.server = None
    
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
        # self.ip = ip

        # the queue is initiated here after asyncio.run() has been called
        # queues made in __init__ attach to another event loop and don't work
        self.msg_queue = asyncio.Queue()

        # if the user entered "listen" wait for another computer to connect
        # otherwise open a connection with the ip address that they entered
        if self.ip == "listen":
            try:
                async with await asyncio.start_server(self.set_streams, port=self.port) as self.server:
                    print("listening on port {}".format(self.port))
                    # serve_forever() serves until callback runs once and calls server.close()
                    await self.server.serve_forever()
            except asyncio.exceptions.CancelledError:
                # server is only cancelled by the callback
                print("Found friend {}".format(self.writer.get_extra_info("peername")))
        else:
            self.reader, self.writer = await asyncio.open_connection(self.ip, port=self.port)
            self.peer, _ = self.writer.get_extra_info("peername")

        # tasks are assigned to a variable to prevent them being garbage collected
        # self.msg_client() sends messages as soon as they enter the queue
        # self.listen() periodically checks if a message has been recieved by self.reader
        # self.updater() continuously updates the UI like Tk.mainloop() would
        self.tasks = [self.updater(), self.listen(), self.msg_client()]
        
        # this waits for tasks that loop forever.
        await asyncio.gather(*self.tasks)        

    async def msg_client(self):
        while True:
            # msg_queue.get() will wait until an item is added to the queue somewhere else
            # when an item is added to msg_queue it is sent and we wait for another item
            msg = await self.msg_queue.get()

            self.writer.write(msg.encode())
            await self.writer.drain()
            
            self.history.configure(state="normal")
            self.history.insert( "end", "\nYou sent: " + msg)
            self.history.configure(state="disabled")
    
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
                
    # adds item to the msg_queue
    # doesn't send data itself because it has to be synchronous
    def send_msg(self):
        self.msg_queue.put_nowait(self.nextmsg.get())
