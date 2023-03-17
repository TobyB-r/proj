from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog
from tkinter import filedialog
from tkinter import messagebox
from PIL import ImageTk

import asyncio
import traceback
from base64 import b64encode
import json
import os

from contact import Contact, GroupChat
import x3dh

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}
pad = {"padx":5, "pady":5}

images = []

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

        self.x3dh_requests[contact] = [(b"", {})]
        
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
            self.group_chats[convo].add_sent(False, message)

            for member in self.group_chats[convo].members:
                self.taskgroup.create_task(
                    self.async_send_msg(member, message.encode("ascii"), {"gc": convo, "members": self.group_chats[convo].members})
                )
        else:
            self.message_history[convo].add_sent(False, message)

            self.taskgroup.create_task(
                self.async_send_msg(convo, message.encode("ascii"))
            )
        
        # sometimes we send empty messages e.g. to allow other user to initialize ratchet
        # message is not added to history if is "" (evaluates to False)
        if message:
            # history is a Tk Text widget that shows messages for the user
            self.history.configure(state="normal")
            self.history.insert("end", "You sent: " + message + "\n")
            self.history.configure(state="disabled")

    async def async_send_msg(self, recipient, message, additional_args={}):
        # request keys if we do not have a contact for them
        # save the message we were going to send to them
        if recipient not in self.message_history:
            if recipient in self.x3dh_requests:
                self.x3dh_requests[recipient].append((message, additional_args))
            else:
                self.x3dh_requests[recipient] = [(message, additional_args)]
            
            await self.request_contact(recipient)
            return
        
        if recipient == self.identity:
            return
        
        header, ciphertext = self.message_history[recipient].double_ratchet.encrypt(message)
        header["recipient"] = recipient
        header["sender"] = self.identity
        header |= additional_args
        text = json.dumps(header).encode("ascii") + b"\n"
        
        print("sent", text)

        await self.sign_send(text)
        self.writer.write(ciphertext)
        await self.writer.drain()

    def send_image(self, *event):
        file = filedialog.askopenfilename(parent=self, title="Select image.")
        
        if file == "": # user closed file dialog before selecting a file
            return
        
        convo = self.convo.get()
        
        if convo == "Select Conversation":
            return
        
        # the user has a group chat selected
        if convo in self.group_chats:
            self.group_chats[convo].add_sent(True, f"{self.identity}_images/" + os.path.basename(file))
            members = self.group_chats[convo].members
            self.taskgroup.create_task(self.async_send_image(members, file, {"gc": convo, "members": members}))
        else: # the user selected a contact with a single other user, not a gc
            self.taskgroup.create_task(self.async_send_image([convo], file, {}))

            self.message_history[convo].add_sent(True, f"{self.identity}_images/" + os.path.basename(file))
    
    # read image from file
    def readfile_blocking(self, filename):
        with open(filename, "rb") as file:
            return file.read()
    
    # write image to file
    def write_image(self, filename, ext, data):
        if not os.path.isdir(f"{self.identity}_images"):
            os.makedirs(f"{self.identity}_images")

        new = f"{self.identity}_images/{filename}{ext}"
        i = 0

        while os.path.exists(new):
            new = f"{self.identity}_images/{filename} ({i}){ext}"
            i += 1

        with open(new, "wb") as file:
            file.write(data)
            return new

    async def async_send_image(self, recipients, file, additional_args):
        loop = asyncio.get_event_loop()
        file_bytes = await loop.run_in_executor(None, self.readfile_blocking, file)
        name, ext = os.path.splitext(os.path.basename(file))

        self.history.configure(state="normal")
        self.history.insert("end", "You sent: " + os.path.basename(file) + "\n")
        image = ImageTk.PhotoImage(data=file_bytes, format=ext[1:])
        images.append(image)
        self.history.image_create("end", image=image)
        self.history.insert("end", "\n")
        self.history.configure(state="disabled")

        await asyncio.gather(
            *(self.async_send_msg(x, file_bytes, {"image": name, "ext": ext, **additional_args}) for x in recipients),
            loop.run_in_executor(None, self.write_image, name, ext, file_bytes))

    def new_gc(self, *args):
        name = simpledialog.askstring("", "Enter chat name", parent=self)
        
        if not name:
            return
        
        x = OptionDialog(self, "", members=list(self.message_history.keys()))

        members = [x.members[i] for i in range(len(x.members)) if x.vars[i].get()]
        members.append(self.identity)
        
        if name:
            self.group_chats[name] = GroupChat(name, members, [])

        self.optionmenu["menu"].add_command(label=name, command=tk._setit(self.convo, name))
        self.convo.set(name)

        for member in members:
            self.taskgroup.create_task(self.async_send_msg(member, b"", {"gc": self.convo.get(), "members": members}))

    def add_user(self, *args):
        x = OptionDialog(self, "", members=list(self.message_history.keys()))

        members = [x.members[i] for i in range(len(x.members)) if x.vars[i].get()]
        
        gc = self.group_chats[self.convo.get()]
        gc.members = list(set(gc.members).union(set(members)))
        
        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, b"", {"gc": self.convo.get(), "members": gc.members}))

    def remove_user(self, *args):
        gc = self.group_chats[self.convo.get()]
        x = OptionDialog(self, "", members=gc.members)
        members = [x.members[i] for i in range(len(x.members)) if not x.vars[i].get()]
        
        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, b"", {"gc": self.convo.get(), "members": members}))

        gc.members = members

    def leave_gc(self, *args):
        gc = self.group_chats[self.convo.get()]
        gc.members.remove(self.identity)

        for member in gc.members:
            self.taskgroup.create_task(self.async_send_msg(member, b"", {"gc": self.convo.get(), "members": gc.members}))

        del self.group_chats[self.convo.get()]
        self.optionmenu["menu"].delete(self.convo.get())
        self.convo.set("Select Conversation")
    
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

                # x3dh is a dictionary of users we requested to start a convesation with and unsent messages to them
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

                # create contact for this user
                self.message_history[contact] = Contact(ratchet, contact, [])

                is_gc = True

                for message, args in self.x3dh_requests[contact]:
                    if "gc" in args:
                        is_gc = False

                    self.taskgroup.create_task(self.async_send_msg(contact, message, args))

                del self.x3dh_requests[contact]
                
                # adding new contact to OptionMenu
                self.optionmenu["menu"].add_command(label=contact, command=tk._setit(self.convo, contact))
                
                if is_gc:
                    self.convo.set(contact)

                continue
            
            ciphertext = await self.reader.readexactly(header["length"])
        
            contact = header["sender"]

            # this is a new contact
            # we initialize x3dh from the header
            if contact not in self.message_history and contact != self.identity:
                if header["alternate"] == self.alternate:
                    ratchet = x3dh.init_receiver(header, self.id_key, self.sp_key, self.otp_keys)

                    # delete the otp key they used if they used one
                    if "otp_ind" in header:
                        self.otp_keys[header["otp_ind"]] = None
                else:
                    ratchet = x3dh.init_receiver(header, self.id_key, self.old_sp_key, self.old_otp_keys)

                    # delete the otp key they used if they used one
                    if "otp_ind" in header:
                        self.old_otp_keys[header["otp_ind"]] = None

                # add contact to message history and to the contact menu
                self.message_history[contact] = Contact(ratchet, contact, [])                
                self.optionmenu["menu"].add_command(label=contact, command=tk._setit(self.convo, contact))

                if "gc" not in header:
                    self.convo.set(contact)
            
            # this message was sent in a group chat
            if "gc" in header:
                # name of the gc
                gc = header["gc"]

                if gc not in self.group_chats: # new group chat we're not part of
                    self.group_chats[gc] = GroupChat(gc, header["members"], [])
                    self.optionmenu["menu"].add_command(label=gc, command=tk._setit(self.convo, gc))
                    self.convo.set(gc)
                else:
                    # updating member set and notifying user about members added or removed
                    new_set = set(header["members"])
                    history_set = set(self.group_chats[gc].members)
                    
                    if new_set != history_set:
                        self.history.configure(state="normal")

                        if self.identity not in new_set:
                            del self.group_chats[gc]
                            self.optionmenu["menu"].delete(gc)
    
                            if self.convo.get() == gc:
                                self.convo.set("Select Conversation")
                            continue

                        for member in history_set - new_set:
                            self.history.insert("end", contact + " removed: " + member + "\n")

                        for member in new_set - history_set:
                            self.history.insert("end", contact + " added: " + member + "\n")

                        self.history.configure(state="disabled")

                        self.group_chats[gc].members = header["members"]   

                message = self.message_history[contact].double_ratchet.decrypt(header, ciphertext)

                if message:
                    if "image" in header and ".." not in header["image"]:# they sent an image
                        name, ext = header["image"], header["ext"]
                        
                        loop = asyncio.get_event_loop()
                        save = await loop.run_in_executor(None, self.write_image, name, ext, message)
                        self.group_chats[gc].add_received(contact, True, save)

                        # if we received in the conversation currently selected show the image onscreen
                        if self.convo.get() == gc:
                            self.history.configure(state="normal")
                            self.history.insert("end", f"{contact} sent: {name}{ext}\n")
                            image = ImageTk.PhotoImage(data=message, format=ext)
                            images.append(image)
                            self.history.image_create("end", image=image)
                            self.history.insert("end", "\n")
                            self.history.configure(state="disabled")
                    else:
                        self.group_chats[gc].add_received(contact, False, message.decode("ascii"))
                        
                        if self.convo.get() == gc:
                            self.history.configure(state="normal")
                            self.history.insert("end", contact + " sent: " + message.decode("ascii") + "\n")
                            self.history.configure(state="disabled")  
            else:
                message = self.message_history[contact].double_ratchet.decrypt(header, ciphertext)            

                if "image" in header and ".." not in header["image"]:# they sent an image
                    name, ext = header["image"], header["ext"]
                    loop = asyncio.get_event_loop()
                    save = await loop.run_in_executor(None, self.write_image, name, ext, message)
                    self.message_history[contact].add_received(True, save)

                    # if we received in the conversation currently selected show the image onscreen
                    if self.convo.get() == contact:
                        self.history.configure(state="normal")
                        self.history.insert("end", f"{contact} sent: {name}{ext}\n")
                        image = ImageTk.PhotoImage(data=message, format=ext)
                        images.append(image)
                        self.history.image_create("end", image=image)
                        self.history.insert("end", "\n")
                        self.history.configure(state="disabled")
                elif message:
                    self.message_history[contact].add_received(False, message.decode("ascii"))

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
        self.taskgroup.create_task(self.async_convo_changed())
    
    async def async_convo_changed(self):
        # configure(state="normal") allows us to edit text in self.history 
        # configure(state="disabled") is done to prevent user from editing the text themselves
        self.history.configure(state="normal")

        # clear text in self.history
        self.history.delete("1.0", "end")
        
        # images are stored in a global variable
        # i think tkinter only has a weak reference to image objects in widgets, this stops gc from deleting them
        global images
        images = []

        # self.convo contains the conversation the user selected to display
        convo = self.convo.get()

        if convo == "Select Conversation":
            self.history.configure(state="disabled")

            # gc_buttons contains tkinter widgets for buttons that appear when a group chat is selected
            if self.gc_buttons != []:
                for button in self.gc_buttons:
                    button.destroy()
                
                self.gc_buttons = []
            
            return

        # self.message_history contains private chats users
        if convo in self.message_history:
            contact = self.message_history[convo]

            # gc_buttons contains tkinter widgets for buttons that appear when a group chat is selected
            if self.gc_buttons != []:
                for button in self.gc_buttons:
                    button.destroy()
                
                self.gc_buttons = []
            
            filenames = [message[2] for message in contact.messages if message[1]]
            loop = asyncio.get_event_loop()
            self.history.configure(state="disabled")
            _images = await asyncio.gather(*[loop.run_in_executor(None, self.readfile_blocking, image) for image in filenames])
            self.history.configure(state="normal")

            # add messages from the contact they selected
            for message in contact.messages:
                if message[1]:
                    if message[0]:
                        self.history.insert("end", f"You sent: {os.path.basename(message[2])}\n")
                    else:
                        self.history.insert("end", f"{contact.name} sent: {os.path.basename(message[2])}\n")
                    data = _images.pop(0)
                    image = ImageTk.PhotoImage(data=data, format=message[2].split(".")[-1])

                    images.append(image)
                    self.history.image_create("end", image=image)            
                    self.history.insert("end", "\n")
                elif message[0]:
                    self.history.insert("end", f"You sent: {message[2]}\n")
                else:
                    self.history.insert("end", f"{contact.name} sent: {message[2]}\n")
                
        elif convo in self.group_chats:
            # buttons that only appear when a group chat is selected
            # if statement is to avoid having to construct them twice if a group chat is selected twice in a row
            if self.gc_buttons == []:
                self.gc_buttons.append(ttk.Button(self.frame3, text="Add Users", command=self.add_user))
                self.gc_buttons[0].grid(row=0, column=3, **pad)
                self.gc_buttons.append(ttk.Button(self.frame3, text="Remove Users", command=self.remove_user))
                self.gc_buttons[1].grid(row=0, column=4, **pad)
                self.gc_buttons.append(ttk.Button(self.frame3, text="Leave Group Chat", command=self.leave_gc))
                self.gc_buttons[2].grid(row=0, column=5, **pad)

            # contact is a group chat
            gc = self.group_chats[convo]
            loop = asyncio.get_event_loop()
            self.history.configure(state="disabled")

            # names of all of the images included sent to or from this contact
            filenames = [message[2] for message in gc.messages if message[1]]

            # allows us to load images asynchronously
            _images = await asyncio.gather(*[loop.run_in_executor(None, self.readfile_blocking, image) for image in filenames])
            self.history.configure(state="normal")

            # add messages from the gc they selected
            for message in gc.messages:
                
                # if the message was an image
                if message[1]:
                    self.history.insert("end", f"{message[0]} sent: {os.path.basename(message[2])}\n")
                    data = _images.pop(0)
                    image = ImageTk.PhotoImage(data=data, format=message[2].split(".")[-1])
                    images.append(image)
                    self.history.image_create("end", image=image)            
                    self.history.insert("end", "\n")
                else:
                    self.history.insert("end", f"{message[0]} sent: {message[2]}\n")
        
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
        # this allows the server to authenticate that messages they receive are actually from us
        signature = b64encode(self.id_key.sign(msg, ec.ECDSA(SHA256())))
        self.writer.write(msg)
        self.writer.write(signature + b"\n")
        await self.writer.drain()

# tkinter requires custom dialogs to be implemented as a class that inherits simpledialog.Dialog
# dialog to choose multiple options from a list, e.g. selecting contacts to include when starting a gc
class OptionDialog(simpledialog.Dialog):
    def __init__(self, *args, members):
        self.members = members
        super().__init__(*args)

    def body(self, master):
        menu_button = ttk.Menubutton(master, text="Select Members")
        menu = tk.Menu(menu_button, tearoff=0)
        # vars is a list of intvars, with a value of 1 or 0 corresponding to if they were selected
        self.vars = []

        for i, option in enumerate(self.members):
            self.vars.append(tk.IntVar())
            menu.add_checkbutton(label=option, variable=self.vars[i])

        menu_button["menu"] = menu
        menu_button.pack()
        