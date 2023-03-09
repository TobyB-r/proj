import os
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}

class DoubleRatchet:
    def __init__(self):
        self.number_sent = 0
        self.number_received = 0
        self.previous_sent = 0
        self.skipped_keys = {}

    # initialisation is different depending on if we start by sending or receiving messages
    # for the sender we perform a dh ratchet step immediately
    # receiver performs first ratchet step when they receive a message
    # the receiver cannot send any messages until it has received one first
    @classmethod
    def init_sender(cls, ad, shared_key, dh_key, init_msg):
        self = cls()
        
        self.dh_sending = ec.generate_private_key(ec.SECP256R1)
        self.dh_receiving = dh_key
        self.root_key, self.ck_sending = kdf_root_key(shared_key, exchange(self.dh_sending, self.dh_receiving)) 
        self.ck_receiving = b""
        self.ad = ad
        # init_msg contains information other users needs for x3dh exchange
        # we attach this to every message we send until we have received a message
        self.init_msg = init_msg

        return self

    @classmethod
    def init_receiver(cls, ad, shared_key, dh_key):
        self = cls()
        
        self.dh_sending = dh_key
        self.dh_receiving = None
        self.root_key = shared_key
        self.ck_sending = b""
        self.ck_receiving = b""
        self.ad = ad
        # initializing as receiver so the other user performed key exchange first
        self.init_msg = None

        return self

    def encrypt(self, plaintext):
        # perform step to get new key for encryption
        self.ck_sending, msg_key = kdf_chain_key(self.ck_sending)
        nonce = os.urandom(16)

        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext, self.ad)

        # header contains information that the other users ratchet needs to decrypt the message
        header = {
            "dh": b64encode(self.dh_sending.public_key().public_bytes(**ser_args)).decode("ascii"),
            "nonce": b64encode(nonce).decode("ascii"),
            "previous_sent": self.previous_sent,
            "number_sent": self.number_sent,
            "length": len(ciphertext)
        }
 
        self.number_sent += 1

        if self.init_msg is not None:
            # add keys from init msg to the header
            header |= self.init_msg

        return header, ciphertext
    
    def decrypt(self, header, ciphertext):
        dh = header["dh"]
        nonce = header["nonce"].encode("ascii")
        
        # we have received a message so the other user has definitely received init message
        self.init_msg = None
        
        if dh + str(header["number_sent"]) in self.skipped_keys:
            # some keys in the chain are "skipped" if messages are received in wrong order
            # there is a skipped key corresponding to this message then use it and delete it
            msg_key = b64decode(self.skipped_keys[dh + str(header["number_sent"])])
            del self.skipped_keys[dh + str(header["number_sent"])]
            
            return AESGCM(msg_key).decrypt(b64decode(nonce), ciphertext, self.ad)
        
        if self.dh_receiving == None or b64encode(self.dh_receiving.public_bytes(**ser_args)).decode("ascii") != dh:
            # other user has performed a dh ratchet step

            # we skip any keys that we missed from the last ratchet
            self.skip_keys(dh, header["previous_sent"])
            self.dh_ratchet(header)

        # skip any keys we missed
        self.skip_keys(dh, header["number_sent"])

        # derive key and decrypt normally
        self.ck_receiving, msg_key = kdf_chain_key(self.ck_receiving)
        self.number_received += 1

        return AESGCM(msg_key).decrypt(b64decode(nonce), ciphertext, self.ad)

    def skip_keys(self, dh, until):
        # skip any keys that have been missed and store them in memory
        while self.number_received < until:
            self.ck_receiving, msg_key = kdf_chain_key(self.ck_receiving)
            self.skipped_keys[dh + str(self.number_received)] = b64encode(msg_key).decode("ascii")
            self.number_received += 1

    def dh_ratchet(self, header):
        self.previous_sent = self.number_sent
        self.number_sent = 0
        self.number_received = 0
        
        # use ecdh to find shared secret to generate new receiving chain key
        self.dh_receiving = serialization.load_der_public_key(b64decode(header["dh"]))
        self.root_key, self.ck_receiving = kdf_root_key(self.root_key, exchange(self.dh_sending, self.dh_receiving))
        
        # generate new dh sending key and find new shared secret to generate new sending chain key
        self.dh_sending = ec.generate_private_key(ec.SECP256R1)
        self.root_key, self.ck_sending = kdf_root_key(self.root_key, exchange(self.dh_sending, self.dh_receiving))

    # used to serialize so that it can be stored in a file
    def serialize(self, password):
        dict = {
            "dh_sending": b64encode(self.dh_sending.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password))).decode("ascii"),
            "root_key": b64encode(self.root_key).decode("ascii"),
            "ck_sending": b64encode(self.ck_sending).decode("ascii"),
            "ck_receiving": b64encode(self.ck_receiving).decode("ascii"),
            "number_sent": self.number_sent,
            "number_received": self.number_received,
            "previous_sent": self.previous_sent,
            "skipped_keys": self.skipped_keys,
            "ad": b64encode(self.ad).decode("ascii"),
            "init_msg": self.init_msg,
        }
        
        if self.dh_receiving is not None:
            dict["dh_receiving"] = b64encode(self.dh_receiving.public_bytes(**ser_args)).decode("ascii")
        else:
            dict["dh_receiving"] = "null"
        
        return json.dumps(dict)

    # used to deserialize when loading contacts when client starts
    @classmethod
    def from_serialized(cls, str, password):
        dict = json.loads(str)
        self = cls()

        self.dh_sending = serialization.load_der_private_key(b64decode(dict["dh_sending"]), password)
        self.root_key = b64decode(dict["root_key"])
        self.ck_sending = b64decode(dict["ck_sending"])
        self.ck_receiving = b64decode(dict["ck_receiving"])
        self.number_sent = dict["number_sent"]
        self.number_received = dict["number_received"]
        self.previous_sent = dict["previous_sent"]
        self.skipped_keys = dict["skipped_keys"]
        self.ad = b64decode(dict["ad"])
        self.init_msg = dict["init_msg"]

        if dict["dh_receiving"] != "null":
            self.dh_receiving = serialization.load_der_public_key(b64decode(dict["dh_receiving"]))
        else:
            self.dh_receiving = None

        return self


# deriving a new chain key and root key from the root key
def kdf_root_key(root_key, salt):
    return (HKDF(SHA256(), 32, salt, b"root->root").derive(root_key), 
            HKDF(SHA256(), 32, root_key, b"root->chain").derive(salt))

# deriving a new message key and chain key from the chain key
def kdf_chain_key(chain_key):
    return (HKDF(SHA256(), 32, chain_key, b"chain->chain").derive(b"x" * 32), 
            HKDF(SHA256(), 32, chain_key, b"chain->message").derive(b"y" * 32))

# DH exchange for the dh ratchet step
def exchange(key_a, key_b):
    secret = key_a.exchange(ec.ECDH(), key_b)
    return HKDF(SHA256(), 32, b"", b"exchange kdf").derive(secret)
