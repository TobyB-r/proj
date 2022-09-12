import asyncio
from tkinter import *
from tkinter import ttk

port = 9001

# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop and using asyncio.sleep() lets asyncio run between updates
class Client(Tk):
    def __init__(self, ip) -> None:
        super().__init__()
        self.ip = ip
        self.nextmsg = StringVar(self)
        self.history = StringVar(self)
        self.server = None
    
    async def set_streams(self, reader, writer):
        print("Connected to server")
        self.reader = reader
        self.writer = writer
        
        if self.server is not None:
            print("closing server")
            self.server.close()
            print("Server closed")

    # begin the program
    async def start_loop(self):
        # queue is initiated here after asyncio.run() has been called
        # queues made in __init__ are attached to another event loop and don't work
        self.msg_queue = asyncio.Queue()

        # if the user entered "listen" wait for another computer to connect
        # otherwise open a connection with the ip address that they entered
        if self.ip == "listen":
            try:
                async with await asyncio.start_server(self.set_streams, port=port) as self.server:
                    print("listening on port {}".format(port))
                    # serve_forever() serves until callback runs once and calls server.close()
                    await self.server.serve_forever()
            except asyncio.exceptions.CancelledError:
                print("Found friend {}".format(self.writer.get_extra_info("peername")))
        else:
            self.reader, self.writer = await asyncio.open_connection(ip, port=port)

        # tasks are assigned to a variable to prevent them being garbage collected
        # self.msg_client() sends messages as soon as the user wants them to be
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
    
    async def listen(self):
        while True:
            msg = await self.reader.read(100)

            if msg:
                self.history.set(msg.decode())
            
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

ip = input("Enter IP: ")

# Client is used just like Tk would be
client = Client(ip)
client.title("Messenger")

# Elements of UI defined
frame = ttk.Frame(client, borderwidth=100)
frame.grid()

ttk.Entry(frame, textvariable=client.nextmsg).pack(side="top", fill="both")
ttk.Label(frame, textvariable=client.history, borderwidth=2, relief="solid").pack(fill="both")
ttk.Button(frame, command=client.send_msg, text="Send").pack(side="bottom", fill="both")

# asyncio event loop is created and program starts
# nothing after this runs
asyncio.run(client.start_loop())
