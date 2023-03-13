from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog
from tkinter import messagebox

import asyncio
import traceback
from base64 import b64encode
import json

from contact import Contact, GroupChat
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
        self.group_chats = {}
        self.x3dh_requests = {}
        self.nextmsg = tk.StringVar(self)
        self.convo = tk.StringVar(self)
        self.taskgroup = asyncio.TaskGroup()
        self.old_sp_key = None
        self.old_otp_keys = []
        self.alternate = False
        self.success = False
        self.gc_buttons = []

    def load_keyset(self, id_key, sp_key, otp_keys, alternate):
        # we save the old keys (from the last time the client was run)
        # allows us to perform any exchanges that happened while offline, as these are the keys the server would have relayed 
        self.id_key = id_key
        self.old_sp_key = sp_key
        self.old_otp_keys = otp_keys
        self.alternate = alternate

    def generate_keyset(self):
        # generate fresh keyset
        # we do this everytime we connect to the server.
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
            
            # we successfully connected to the server
            self.success = True

            await self.sign_send(json.dumps({
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
    
    # tkinter requires commands for events to be functions not coroutines so we use this instead
    # asks the user for the name and then schedules for the coroutine to run
    def new_contact(self):
        contact = simpledialog.askstring("", "Enter username", parent=self)

        self.x3dh_requests[contact] = [("", {})]
        
        # TaskGroup schedules for the coroutine to be run soon
        # this doesn't block while the coroutine executes
        self.taskgroup.create_task(
            self.request_contact(contact)
        )
    
    # coroutine to send a message to the server requesting x3dh keys for a certain user
    async def request_contact(self, recipient):
        if recipient == self.identity:
            return
        
        msg = { "request": recipient }

        header = json.dumps(msg).encode("ascii") + b"\n"
        await self.sign_send(header)
    
    # method used by the send button, has to be synchronous for tkinter
    # send message is async so it schedules it with the taskgroup
    def send_msg(self, *_):
        convo = self.convo.get()
        message = self.nextmsg.get()
        
        if convo == self.identity or convo == "Select Conversation":
            return
        
        if convo in self.group_chats:
            self.group_chats[convo].add_sent(message)

            for member in self.group_chats[convo].members:
                self.taskgroup.create_task(
                    self.async_send_msg(member, message, {"gc": convo, "members": self.group_chats[convo].members})
                )
        else:
            self.message_history[convo].add_sent(message)

            self.taskgroup.create_task(
                self.async_send_msg(convo, message)
            )
        
        # sometimes we send empty messages e.g. to allow other user to initialize ratchet
        # message is not added to history if is "" (evaluates to False)
        if message:
            # history is a Tk Text widget that shows messages for the user
            self.history.configure(state="normal")
            self.history.insert("end", "You sent: " + message + "\n")
            self.history.configure(state="disabled")

    async def async_send_msg(self, recipient, message, additional_args={}):
        print("async_send_msg", recipient, message, additional_args)

        if recipient not in self.message_history:
            if recipient in self.x3dh_requests:
                self.x3dh_requests[recipient].append((message, additional_args))
            else:
                self.x3dh_requests[recipient] = [(message, additional_args)]
            
            await self.request_contact(recipient)
            return
        
        if recipient == self.identity:
            return
        
        header, ciphertext = self.message_history[recipient].double_ratchet.encrypt(message.encode("ascii"))
        header["recipient"] = recipient
        header["sender"] = self.identity
        header |= additional_args
        text = json.dumps(header).encode("ascii") + b"\n"
        
        print("sent", text)

        await self.sign_send(text)
        self.writer.write(ciphertext)
        await self.writer.drain()

    def new_gc(self, *args):
        name = simpledialog.askstring("", "Enter chat name", parent=self)
        x = OptionDialog(self, "", members=list(self.message_history.keys()))

        members = [x.members[i] for i in range(len(x.members)) if x.vars[i].get()]
        members.append(self.identity)
        
        if name:
            self.group_chats[name] = GroupChat(name, members, [])

        self.optionmenu["menu"].add_command(label=name, command=tk._setit(self.convo, name))
        self.convo.set(name)

        for member in members:
            self.taskgroup.create_task(self.async_send_msg(member, "", {"gc": self.convo.get(), "members": members}))

    def add_user(self, *args):
        username = simpledialog.askstring("", "Enter username", parent=self)

        if username not in self.message_history:
            messagebox.showerror("Error", "Add user as a contact first.")
            return
        
        gc = self.group_chats[self.convo.get()]
        gc.members.append(username)
        
        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, "", {"gc": self.convo.get(), "members": gc.members}))

    def remove_user(self, *args):
        username = simpledialog.askstring("", "Enter username", parent=self)
        gc = self.group_chats[self.convo.get()]
        gc.members.remove(username)
        
        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, "", {"gc": self.convo.get(), "members": gc.members}))

    def leave_gc(self, *args):
        gc = self.group_chats[self.convo.get()]
        gc.members.remove(self.identity)

        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, "", {"gc": self.convo.get(), "members": gc.members}))
    
    # waits for messages to be received
    async def listen(self):
        while self.running:
            print("waiting for message")
            header = await self.reader.readline()

            # server indicates that we requested x3dh for a user that does not exist
            if header == b"{}\n":
                messagebox.showerror("Error", "Requested user does not exist.")
                continue

            # reader disconnected
            if header == b"":
                # writer.is_closing means that we called writer.close(), we disconnected not the server
                if not self.writer.is_closing():
                    messagebox.showerror("Error", "Server disconnected. Please restart program.")
                    self.taskgroup._abort()
                
                return

            print("received", header)
            header = json.loads(header.decode("ascii"))

            # response to a request for x3dh keys
            if "identity" in header:
                contact = header["identity"]

                if contact not in self.x3dh_requests:
                    continue
                
                try:
                    ratchet = x3dh.init_sender(self.id_key, header)
                except InvalidSignature:
                    messagebox.showerror("Error", f"Failed to verify requested contact {contact}'s keys.")
                    continue
                except Exception:
                    messagebox.showerror("Error", f"Failed to add contact {contact}.")
                    continue

                self.message_history[contact] = Contact(ratchet, contact, [])

                flag = True

                for message, args in self.x3dh_requests[contact]:
                    if "gc" in args:
                        flag = False

                    self.taskgroup.create_task(self.async_send_msg(contact, message, args))

                del self.x3dh_requests[contact]
                
                # adding new contact to OptionMenu
                self.optionmenu["menu"].add_command(label=contact, command=tk._setit(self.convo, contact))
                
                if flag:
                    self.convo.set(contact)

                continue
            
            ciphertext = await self.reader.readexactly(header["length"])
        
            contact = header["sender"]

            # this is a new contact
            # we initialize x3dh from the header
            if contact not in self.message_history and contact != self.identity:
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

                if "gc" not in header:
                    self.convo.set(contact)
            
            if "gc" in header:
                gc = header["gc"]

                if gc not in self.group_chats:
                    self.group_chats[gc] = GroupChat(gc, header["members"], [])
                    self.optionmenu["menu"].add_command(label=gc, command=tk._setit(self.convo, gc))
                    self.convo.set(gc)
                else:
                    new_set = set(header["members"])
                    history_set = set(self.group_chats[gc].members)
                    
                    if new_set != history_set:
                        self.history.configure(state="normal")

                        if self.identity not in new_set:
                            self.convo.set("Select Conversation")
                            del self.group_chats[gc]
                            continue

                        for member in history_set - new_set:
                            self.history.insert("end", contact + " removed: " + member + "\n")

                        for member in new_set - history_set:
                            self.history.insert("end", contact + " added: " + member + "\n")

                        self.history.configure(state="disabled")

                        self.group_chats[gc].members = header["members"]   

                message = self.message_history[contact].double_ratchet.decrypt(header, ciphertext)

                if message:
                    if self.convo.get() == gc:
                        self.group_chats[gc].add_received(contact, message.decode("ascii"))
                        self.history.configure(state="normal")
                        self.history.insert("end", contact + " sent: " + message.decode("ascii") + "\n")
                        self.history.configure(state="disabled")  
            else:
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

    # the user select a different conversation
    # fill history with the correct messages
    def convo_changed(self, *_):
        # configure(state="normal") allows us to edit text in self.history 
        self.history.configure(state="normal")
        # clear text in self.history
        self.history.delete("1.0", "end")

        convo = self.convo.get()

        if convo == "Select Conversation":
            # prevents the user from being able to edit text in self.history themselves
            self.history.configure(state="disabled")


        if convo in self.message_history:
            contact = self.message_history[convo]

            if self.gc_buttons != []:
                for button in self.gc_buttons:
                    button.destroy()
                
                self.gc_buttons = []
            
            # add messages from the contact they selected
            for message in contact.messages:
                if message[1]:
                    if message[0]:
                        self.history.insert("end", f"You sent: {message[1]}\n")
                    else:
                        self.history.insert("end", f"{contact.name} sent: {message[1]}\n")
        else:
            if self.gc_buttons == []:
                self.gc_buttons.append(ttk.Button(self.frame3, text="Add User", command=self.add_user))
                self.gc_buttons[0].grid(row=0, column=3, padx=5, pady=5)
                self.gc_buttons.append(ttk.Button(self.frame3, text="Remove User", command=self.remove_user))
                self.gc_buttons[1].grid(row=0, column=4, padx=5, pady=5)
                self.gc_buttons.append(ttk.Button(self.frame3, text="Leave Group Chat", command=self.leave_gc))
                self.gc_buttons[2].grid(row=0, column=5, padx=5, pady=5)

            # contact is a group chat
            for message in self.group_chats[convo].messages:
                self.history.insert("end", f"{message[0]} sent: {message[1]}\n")
        
        # prevents the user from being able to edit text in self.history themselves
        self.history.configure(state="disabled")
   
    # called by tkinter when user clicks the X button to close window
    def close(self):
        self.running = False
        self.taskgroup.create_task(self.cleanup())

    async def cleanup(self):
        # closes the connection to the server
        self.writer.close()
        await self.writer.wait_closed()

    async def sign_send(self, msg):
        # we sign every message we send to the server with our id_key
        # this allows the server to authenticate messages they receive are actually from us
        signature = b64encode(self.id_key.sign(msg, ec.ECDSA(SHA256())))
        self.writer.write(msg)
        self.writer.write(signature + b"\n")
        await self.writer.drain()

# class for the dialog that appears to choose contacts to select when the user starts a gc
class OptionDialog(simpledialog.Dialog):
    def __init__(self, *args, members):
        self.members = members
        super().__init__(*args)

    def body(self, master):
        menu_button = ttk.Menubutton(master, text="Select Members")
        self.vars = []
        menu = tk.Menu(menu_button, tearoff=0)

        for i, option in enumerate(self.members):
            self.vars.append(tk.IntVar())
            menu.add_checkbutton(label=option, variable=self.vars[i])

        menu_button["menu"] = menu
        menu_button.pack()
        