import asyncio
import tkinter as tk
from tkinter.ttk import *
from tkinter import messagebox
from client import Client
from contact import Contact
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import *
import os
import base64

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}

port = 9001
pad = {"padx":5, "pady":5}

# Client is used just like Tk would be
client = Client(port)
client.title("Messenger")
client.geometry("600x400")

frame1 = Frame(client)
frame1.pack(expand=1, fill="both", **pad)
frame1.columnconfigure(0, weight=1)
frame1.rowconfigure(2, weight=1)

# Elements of UI defined
Label(frame1, text="Instantaneous Messenger", font=("Arial", 19)).grid(row=0, columnspan=3, **pad)

frame2 = Frame(frame1)
frame2.grid(row=2, columnspan=3, sticky="news", **pad)
frame2.columnconfigure(0, weight=1)
frame2.rowconfigure(0, weight=1)

client.history = tk.Text(frame2, height=0, width=0, relief="solid")
client.history.grid(row=0, column=0, sticky="news")

client.optionmenu = OptionMenu(frame1, client.convo, "Select Contact")
client.convo.trace("w", client.convo_changed)
client.optionmenu.grid(row=1, columnspan=3, **pad)

scroll = Scrollbar(frame2, orient="vertical", command=client.history.yview)
client.history.configure(yscrollcommand=scroll.set)
scroll.grid(row=0, column=1, sticky="ns")

entry = Entry(frame1, textvariable=client.nextmsg)
entry.grid(row=3, column=0, sticky="ew", **pad)
entry.bind("<Return>", client.send_msg)
Button(frame1, text="Send", command=client.send_msg).grid(row=3, column=1, **pad)
Button(frame1, text="New Contact", command=client.new_contact).grid(row=3, column=2, **pad)

# asking user for their username and IP of server
client.ip = tk.simpledialog.askstring("", "Enter server IP", parent=client)
client.identity = tk.simpledialog.askstring("", "Enter username", parent=client)
client.password = tk.simpledialog.askstring("", "Enter password", parent=client, show="*").encode("ascii")
client.history.insert("end", f"Your username is: {client.identity}\nConnecting to IP: {client.ip}")
client.history.configure(state="disabled")

priv_ser_args = {
    "encoding": serialization.Encoding.DER,
    "format": serialization.PrivateFormat.PKCS8,
    "encryption_algorithm": serialization.BestAvailableEncryption(client.password)
}

# called when the user closes the window
client.protocol("WM_DELETE_WINDOW", client.close)

try:
    if os.path.exists(f"keys_{client.identity}.txt"):
        with open(f"keys_{client.identity}.txt", "r") as file:
            alternate = file.readline() == "True\n"
            id_key = serialization.load_der_private_key(base64.b64decode(file.readline().rstrip()), client.password)
            sp_key = serialization.load_der_private_key(base64.b64decode(file.readline().rstrip()), client.password)
            otp_keys = []

            for line in file:
                if line != "\n":
                    otp_keys.append(serialization.load_der_private_key(base64.b64decode(line.rstrip()), client.password))
                else:
                    otp_keys.append(None)
            
            client.load_keyset(id_key, sp_key, otp_keys, alternate)
    else:
        client.id_key = ec.generate_private_key(ec.SECP256R1)

    client.generate_keyset()

    if os.path.exists(f"message_history_{client.identity}.txt"):
        with open(f"message_history_{client.identity}.txt", "r") as file:
            for line in file:
                if line:
                    contact = Contact.from_serialized(line, client.password)
                    client.message_history[contact.name] = contact
                    client.optionmenu["menu"].add_command(label=contact.name, command=tk._setit(client.convo, contact.name))
except ValueError:
    messagebox.showerror("Error", "Password or username is incorrect.")

# asyncio event loop is created and program starts
# nothing after this runs until client it is closed
asyncio.run(client.start_loop())

if client.message_history:
    with open(f"message_history_{client.identity}.txt", "w") as file:
        for contact in client.message_history.values():
            file.write(contact.serialize(client.password) + "\n")

with open(f"keys_{client.identity}.txt", "wb") as file:
    file.write(str(client.alternate).encode("ascii") + b"\n")
    file.write(base64.b64encode(client.id_key.private_bytes(**priv_ser_args)) + b"\n")
    file.write(base64.b64encode(client.sp_key.private_bytes(**priv_ser_args)) + b"\n")
    
    for key in client.otp_keys:
        if key is not None:
            file.write(base64.b64encode(key.private_bytes(**priv_ser_args)) + b"\n")
        else:
            file.write(b"\n")
