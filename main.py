import asyncio
from tkinter import *
from tkinter import ttk
from client import Client

ip = input("Enter IP: ")
port = 9001

# Client is used just like Tk would be
client = Client(ip, port)
client.title("Messenger")
client.geometry("600x400")

# Elements of UI defined
frame = ttk.Frame(client, border=30, relief="solid")
frame.pack(fill="both", expand=1)

ttk.Entry(frame, textvariable=client.nextmsg).pack(side="top", fill="both", pady=5)
ttk.Label(frame, textvariable=client.history, borderwidth=2, relief="solid", anchor="nw").pack(fill="both", expand=1, pady=5)
ttk.Button(frame, command=client.send_msg, text="Send").pack(side="bottom", fill="both", pady=5)

# asyncio event loop is created and program starts
# nothing after this runs

asyncio.run(client.start_loop())
