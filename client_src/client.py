import asyncio
import tkinter as tk
from tkinter import simpledialog
import json

# used to test the ui without a server or networking
ONLINE = True

# client class updates the ui and controls networking
# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop with a function that uses asyncio.sleep() lets asyncio run between updates
class Client(tk.Tk):
    def __init__(self, port, message_history):
        super().__init__()
        self.running = True
        self.port = port
        self.message_history = message_history
        self.nextmsg = tk.StringVar(self)
        self.msg_queue = asyncio.Queue()
        self.convo = tk.StringVar(self)
        self.ip = None
        self.history = None
        self.optionmenu = None
        self.identity = None

    # begin the program
    async def start_loop(self):
        if ONLINE:
            handshake = json.dumps({"identity": self.identity})
            
            self.reader, self.writer = await asyncio.open_connection(self.ip, port=self.port)
            self.writer.write(handshake.encode("ascii"))
            self.writer.write(b"\n")
            await self.writer.drain()

            coro = [self.updater(), self.msg_client(), self.listen()]
        else:
            coro = [self.updater()]

        # coroutines that happen continuously in the background
        # self.msg_client() sends messages when they enter msg_queue
        # self.listen() periodically checks if a message has been recieved by self.reader
        # self.updater() handles the UI like Tk.mainloop() would
        try:
            self.coros = asyncio.gather(*coro)
            await self.coros
        except asyncio.CancelledError:
            pass
    
    # waits for messages in the queue then sends them
    async def msg_client(self):
        while self.running:
            # msg_queue.get() will wait until an item is added to the queue
            msg = await self.msg_queue.get()

            # checks if a recipient was selected when the message was sent
            if msg["recipient"]:
                text = json.dumps(msg)
                self.writer.write(text.encode("ascii"))
                self.writer.write(b"\n")
                await self.writer.drain()
                
                # history is a Tk Text widget that shows messages for the user
                self.history.configure(state="normal")
                self.history.insert("end", "You sent: " + msg["message"] + "\n")
                self.history.configure(state="disabled")
                self.message_history[msg["recipient"]].append((True, msg["message"]))
    
    # periodically checks if a message has been recieved
    async def listen(self):
        while self.running:
            text = await self.reader.readline()

            if text:
                print(text)
                msg = json.loads(text)
                sender = msg["sender"]

                # if the message is from the user we're talking to
                if self.convo.get() == sender:
                    self.history.configure(state="normal")
                    self.history.insert("end", sender + " sent: " + msg["message"] + "\n")
                    self.history.configure(state="disabled")
                
                # add the message to the list to be added to csv
                if sender in self.message_history:  
                    self.message_history[sender].append((False, msg["message"]))
                else:
                    self.message_history[sender] = [(False, msg["message"])]
                    self.optionmenu["menu"].add_command(label=sender,
                    command=lambda *_: self.convo.set(sender))

    # replacement for Tk.mainloop()
    async def updater(self):
        # sets a flag that Tk.mainloop() usually does, prevents some bugs
        self.willdispatch()

        while self.running:
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
            "recipient": self.convo.get(),
        })

    # the user select a different conversation
    # fill history with the correct messages
    def convo_changed(self, *_):
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")

        for message in self.message_history[self.convo.get()]:
            if message[0]:
                self.history.insert("end", "You sent: " + message[1] + "\n")
            else:
                self.history.insert("end", self.convo.get() + " sent: " + message[1] + "\n")
        
        self.history.configure(state="disabled")

    def new_contact(self):
        contact = simpledialog.askstring("", "Enter username", parent=self)
        
        if contact not in self.message_history and contact:
            self.message_history[contact] = []
            self.optionmenu["menu"].add_command(label=contact,
            command=lambda *_: self.convo.set(contact))
   
    def close(self):
        self.running = False
        self.coros.cancel()