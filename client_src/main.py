import asyncio
import tkinter as tk
from tkinter.ttk import *
from tkinter import simpledialog
from client import Client
import csv
import itertools

port = 9001
identity = "windows"
message_history = {}
pad = {"padx":5, "pady":5}

with open("message_history.csv", "r") as file:
    reader = csv.reader(file)
    
    for line in reader:
        result = []

        for i in range(1, len(line), 2):
            result.append((line[i] == "True", line[i+1]))
        
        message_history[line[0]] = result

# Client is used just like Tk would be
client = Client(port, message_history)
client.title("Messenger")
client.geometry("600x400")

frame = Frame(client)
frame.pack(expand=1, fill="both", **pad)
frame.columnconfigure(0, weight=1)
frame.rowconfigure(2, weight=1)

# Elements of UI defined
Label(frame, text="Instantaneous Messenger", font=("Arial", 19)).grid(row=0, columnspan=3, **pad)

client.combobox = Combobox(frame)
client.combobox.bind("<<ComboboxSelected>>", client.convo_changed)
client.combobox["values"] = list(message_history.keys())
client.combobox.grid(row=1, columnspan=3, **pad)

frame1 = Frame(frame)
frame1.grid(row=2, columnspan=3, sticky="news", **pad)
frame1.columnconfigure(0, weight=1)
frame1.rowconfigure(0, weight=1)

client.history = tk.Text(frame1, height=0, width=0, relief="solid")
client.history.grid(row=0, column=0, sticky="news")

scroll = Scrollbar(frame1, orient="vertical", command=client.history.yview)
client.history.configure(yscrollcommand=scroll.set)
scroll.grid(row=0, column=1, sticky="ns")

Entry(frame, textvariable=client.nextmsg).grid(row=3, column=0, sticky="ew", **pad)
Button(frame, text="Send", command=client.send_msg).grid(row=3, column=1, **pad)
Button(frame, text="New Contact", command=client.new_contact).grid(row=3, column=2, **pad)

client.ip = tk.simpledialog.askstring("", "Enter server IP", parent=client)
client.identity = tk.simpledialog.askstring("", "Enter username", parent=client)
client.history.insert("end", f"Your username is: {client.identity}\n")
client.history.insert("end", f"Connecting to IP: {client.ip}")
client.history.configure(state="disabled")

client.protocol("WM_DELETE_WINDOW", client.close)

# asyncio event loop is created and program starts
# nothing after this runs

asyncio.run(client.start_loop())

with open("message_history.csv", "w", newline="") as file:
    writer = csv.writer(file)
    
    for (contact, history) in client.message_history.items():
        writer.writerow([contact, *itertools.chain(*history)])
