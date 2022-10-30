import asyncio
import tkinter
from tkinter.ttk import *
from client import Client

ip = input("Enter IP: ")
port = 9001
identity = "windows"

message_history = {
    "linux": [(False, "i need"), (False, "i sneed")],
    "femboy": [(True, "other")]
}

# Client is used just like Tk would be
client = Client(ip, port, identity, message_history)
client.title("Messenger")
client.geometry("600x400")

# Elements of UI defined
frame = Frame(client)
frame.pack(fill="both", expand=1, padx=5, pady=5)

Label(frame, text="Instantaneous Messenger", font=("Arial", 19)).pack(side="top", padx=5, pady=5)

client.combobox = Combobox(frame)
client.combobox.pack(side="top", padx=5, pady=5)
client.combobox.bind("<<ComboboxSelected>>", client.convo_changed)
client.combobox["values"] = list(message_history.keys())

frame2 = Frame(frame)
frame2.pack(fill="both", expand=1, padx=5, pady=5)

client.history = tkinter.Text(frame2, height=0, width=0, relief="solid", padx=1)
client.history.pack(side="left", fill="both", expand=1)
client.history.insert("end", f"Connecting to IP: {ip}")
client.history.configure(state="disabled")

scroll = Scrollbar(frame2, orient="vertical", command=client.history.yview)
scroll.pack(side="right", fill="y")
client.history.configure(yscrollcommand=scroll.set)

Entry(frame, textvariable=client.nextmsg).pack(fill="x", padx=30, pady=5)
Button(frame, text="Send", command=client.send_msg).pack(side="bottom", padx=5, pady=5)

# asyncio event loop is created and program starts
# nothing after this runs

asyncio.run(client.start_loop())
