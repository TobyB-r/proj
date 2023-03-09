from double_ratchet import DoubleRatchet
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import os
from base64 import b64encode, b64decode

class Contact:
    def __init__(self, double_ratchet, name, messages):
        self.double_ratchet = double_ratchet
        self.messages = messages
        self.name = name
        print(name, "; initializing with", messages)

    @classmethod
    def from_serialized(cls, string, password):
        name, encrypted, double_ratchet = string.split("\\")
        encrypted = json.loads(encrypted)
        key = HKDF(SHA256(), 32, b"", b"dr_storage").derive(password)
        ad = name.encode("ascii")  

        messages = []

        for msg in encrypted:
            messages.append([msg[0], AESGCM(key).decrypt(b64decode(msg[1]), b64decode(msg[2]), ad).decode("ascii")])

        return cls(DoubleRatchet.from_serialized(double_ratchet, password), name, messages)
      
    def serialize(self, password):
        encrypted = []
        key = HKDF(SHA256(), 32, b"", b"dr_storage").derive(password)
        ad = self.name.encode("ascii")

        for i in range(len(self.messages)):
            nonce = os.urandom(16)
            encrypted.append([self.messages[i][0], b64encode(nonce).decode("ascii"), b64encode(AESGCM(key).encrypt(nonce, self.messages[i][1].encode("ascii"), ad)).decode("ascii")])

        return "\\".join([self.name, json.dumps(encrypted), self.double_ratchet.serialize(password)])

    def add_sent(self, msg):
        print(self.name, "; adding sent", msg, "to", self.messages)
        self.messages.append([True, msg])
    
    def add_received(self, msg):
        print(self.name, "; adding received", msg, "to", self.messages)
        self.messages.append([False, msg])