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

    @classmethod
    def from_serialized(cls, string, password, salt):
        name, encrypted, double_ratchet = string.split("\\")
        encrypted = json.loads(encrypted)

        # deriving values for AES from the password and name
        key = HKDF(SHA256(), 32, salt, b"dr_storage").derive(password)
        ad = name.encode("ascii")  

        messages = []

        for msg in encrypted:
            messages.append([msg[0], msg[1], AESGCM(key).decrypt(b64decode(msg[2]), b64decode(msg[3]), ad).decode("ascii")])

        return cls(DoubleRatchet.from_serialized(double_ratchet, password), name, messages)
      
    def serialize(self, password, salt):
        encrypted = []

        # deriving values for AES from the password and name
        key = HKDF(SHA256(), 32, salt, b"dr_storage").derive(password)
        ad = self.name.encode("ascii")

        for i in range(len(self.messages)):
            nonce = os.urandom(16)
            encrypted.append([self.messages[i][0], self.messages[i][1], b64encode(nonce).decode("ascii"), b64encode(AESGCM(key).encrypt(nonce, self.messages[i][2].encode("ascii"), ad)).decode("ascii")])

        return "\\".join([self.name, json.dumps(encrypted), self.double_ratchet.serialize(password)])

    def add_sent(self, isimg, msg):
        # first index indicates message was sent by us
        self.messages.append([True, isimg, msg])
    
    def add_received(self, isimg, msg):
        # first index indicates message was sent by the other user
        self.messages.append([False, isimg, msg])

class GroupChat():
    def __init__(self, name, members, messages):
        self.name = name
        self.members = members
        self.messages = messages
    
    def add_received(self, sender, isimg, message):
        self.messages.append([sender, isimg, message])
    
    def add_sent(self, isimg, message):
        self.messages.append(["You", isimg, message])

    @classmethod
    def from_serialized(cls, string, password, salt):
        name, members, encrypted = string.split("\\")
        members = json.loads(members)
        encrypted = json.loads(encrypted)

        # deriving values for AES from the password and name
        key = HKDF(SHA256(), 32, salt, b"dr_storage").derive(password)
        ad = name.encode("ascii")  

        messages = []

        for msg in encrypted:
            messages.append([msg[0], msg[1], AESGCM(key).decrypt(b64decode(msg[2]), b64decode(msg[3]), ad).decode("ascii")])

        return cls(name, members, messages)
      
    def serialize(self, password, salt):
        encrypted = []

        # deriving values for AES from the password and name
        key = HKDF(SHA256(), 32, salt, b"dr_storage").derive(password)
        ad = self.name.encode("ascii")

        for i in range(len(self.messages)):
            nonce = os.urandom(16)
            encrypted.append([self.messages[i][0], self.messages[i][1], b64encode(nonce).decode("ascii"), b64encode(AESGCM(key).encrypt(nonce, self.messages[i][2].encode("ascii"), ad)).decode("ascii")])

        return "\\".join([self.name, json.dumps(self.members), json.dumps(encrypted)])
