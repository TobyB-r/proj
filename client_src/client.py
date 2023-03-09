from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox

import asyncio
import traceback
from base64 import b64encode, b64decode
import json
import time

from contact import Contact
import x3dh

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}

# used to test the ui without a server or networking
ONLINE = True

# client class updates the ui and controls networking
# subclassing Tk because Tk.mainloop() busy waits and blocks asyncio from executing
# replacing mainloop with a function that uses asyncio.sleep() lets asyncio run between updates
class Client(tk.Tk):
    def __init__(self, port):
        super().__init__()
        self.running = True
        self.port = port
        self.message_history = {}
        self.nextmsg = tk.StringVar(self)
        self.convo = tk.StringVar(self)
        self.taskgroup = asyncio.TaskGroup()
        self.old_sp_key = None
        self.old_otp_keys = []
        self.alternate = False

    def load_keyset(self, id_key, sp_key, otp_keys, alternate):
        self.id_key = id_key
        self.old_sp_key = sp_key
        self.old_otp_keys = otp_keys
        self.alternate = alternate

    def generate_keyset(self):
        self.sp_key = ec.generate_private_key(ec.SECP256R1)
        self.sp_key_sig = self.id_key.sign(self.sp_key.public_key().public_bytes(**ser_args), ec.ECDSA(SHA256()))
        self.otp_keys = [ec.generate_private_key(ec.SECP256R1) for _ in range(10)]
        self.alternate = not self.alternate

    # begin the program
    async def start_loop(self):
        if ONLINE:
            try:
                self.reader, self.writer = await asyncio.open_connection(self.ip, port=self.port)
            except ConnectionRefusedError:
                messagebox.showerror("Error", "Failed to connect to server. Please try again in a few minutes.")
                return

            await self.send(json.dumps({
                "identity": self.identity,
                "x3dh": {
                    "alternate": self.alternate,
                    "id_key": b64encode(self.id_key.public_key().public_bytes(**ser_args)).decode("ascii"),
                    "sp_key": b64encode(self.sp_key.public_key().public_bytes(**ser_args)).decode("ascii"),
                    "sp_key_sig": b64encode(self.sp_key_sig).decode("ascii"),
                    "otp_keys": [b64encode(key.public_key().public_bytes(**ser_args)).decode("ascii") for key in self.otp_keys]
                }
            }).encode("ascii") + b"\n")
        
        # coroutines that happen continuously in the background
        # self.listen() periodically checks if a message has been recieved by self.reader
        # self.updater() handles the UI like Tk.mainloop() would
        try:
            async with self.taskgroup:
                self.taskgroup.create_task(self.updater())

                if ONLINE:
                    self.taskgroup.create_task(self.listen())
        except ConnectionResetError:
            messagebox.showerror("Error", "Server disconnected unexpectedly. Please restart the program.")
        except Exception as e:
            print(e)
            print(traceback.format_exc())
    
    async def request_contact(self, recipient):
        msg = { "request": recipient }

        header = json.dumps(msg).encode("ascii") + b"\n"
        await self.send(header)
    
    async def async_send_msg(self, recipient, message):
        header, ciphertext = self.message_history[recipient].double_ratchet.encrypt(message.encode("ascii"))
        header["recipient"] = recipient
        header["sender"] = self.identity

        text = json.dumps(header).encode("ascii") + b"\n"
        await self.send(text)
        self.writer.write(ciphertext)
        await self.writer.drain()
        
        if message:
            # history is a Tk Text widget that shows messages for the user
            self.history.configure(state="normal")
            self.history.insert("end", "You sent: " + message + "\n")
            self.history.configure(state="disabled")
            self.message_history[recipient].add_sent(message)
    
    # periodically checks if a message has been recieved
    async def listen(self):
        while self.running:
            header = await self.reader.readline()

            if header == b"{}\n":
                messagebox.showerror("Error", "Requested user does not exist.")
                continue
            if header == b"":
                if not self.writer.is_closing():
                    messagebox.showerror("Error", "Server disconnected. Please restart program.")
                    self.taskgroup._abort()
                
                return

            header = json.loads(header.decode("ascii"))

            if "identity" in header:
                contact = header["identity"]

                if not contact or contact in self.message_history:
                    continue
                
                try:
                    ratchet = x3dh.init_sender(self.id_key, header)
                except InvalidSignature:
                    messagebox.showerror("Error", "Failed to verify requested contact's keys.")

                self.message_history[contact] = Contact(ratchet, contact, [])
                await self.async_send_msg(contact, "")
                
                self.optionmenu["menu"].add_command(label=contact, command=tk._setit(self.convo, contact))
                self.convo.set(contact)
            else:
                ciphertext = await self.reader.readexactly(header["length"])
            
                contact = header["sender"]

                if contact not in self.message_history:
                    if header["alternate"] == self.alternate:
                        ratchet = x3dh.init_receiver(header, self.id_key, self.sp_key, self.otp_keys)

                        if "otp_ind" in header:
                            self.otp_keys[header["otp_ind"]] = None
                    else:
                        ratchet = x3dh.init_receiver(header, self.id_key, self.old_sp_key, self.old_otp_keys)
    
                        if "otp_ind" in header:
                            self.old_otp_keys[header["otp_ind"]] = None

                    self.message_history[contact] = Contact(ratchet, contact, [])
                    
                    self.optionmenu["menu"].add_command(label=contact, command=tk._setit(self.convo, contact))
                    self.convo.set(contact)

                message = self.message_history[contact].double_ratchet.decrypt(header, ciphertext)
                self.message_history[contact].add_received(message.decode("ascii"))
                
                if message:
                    # if the message is from the user we're talking to
                    if self.convo.get() == contact:
                        self.history.configure(state="normal")
                        self.history.insert("end", contact + " sent: " + message.decode("ascii") + "\n")
                        self.history.configure(state="disabled")

    # replacement for Tk.mainloop()
    async def updater(self):
        # sets a flag that Tk.mainloop() usually does, prevents some bugs
        self.willdispatch()

        while self.running:
            # runs all events to do with tkinter and user input
            # asyncio.sleep() lets io happen in background
            self.update()
            await asyncio.sleep(0.02)

    # method used by the send button, has to be synchronous for tkinter
    # send message is async so it schedules it with the taskgroup
    def send_msg(self, *_):
        if self.convo.get() != "Select Contact":
            self.taskgroup.create_task(
                self.async_send_msg(self.convo.get(), self.nextmsg.get())
            )

    def new_contact(self):
        contact = simpledialog.askstring("", "Enter username", parent=self)
        
        self.taskgroup.create_task(
            self.request_contact(contact)
        )

    # the user select a different conversation
    # fill history with the correct messages
    def convo_changed(self, *_):
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        contact = self.convo.get()

        for message in self.message_history[contact].messages:
            if message[1]:
                if message[0]:
                    self.history.insert("end", "You sent: " + message[1] + "\n")
                else:
                    self.history.insert("end", contact + " sent: " + message[1] + "\n")
        
        self.history.configure(state="disabled")
   
    def close(self):
        self.running = False
        self.taskgroup.create_task(self.cleanup())

    async def cleanup(self):
        self.writer.close()
        await self.writer.wait_closed()

    async def send(self, msg):
        signature = b64encode(self.id_key.sign(msg, ec.ECDSA(SHA256())))
        self.writer.write(msg)
        self.writer.write(signature + b"\n")
        await self.writer.drain()
