from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
from double_ratchet import DoubleRatchet

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}

def init_sender(id_key, header):
    eph_key = ec.generate_private_key(ec.SECP256R1)
    
    peer_sp_key = base64.b64decode(header["sp_key"])
    peer_id_key = serialization.load_der_public_key(base64.b64decode(header["id_key"]))
    peer_key_sig = base64.b64decode(header["sp_key_sig"])

    peer_id_key.verify(peer_key_sig, peer_sp_key, ec.ECDSA(SHA256()))

    peer_sp_key = serialization.load_der_public_key(peer_sp_key)

    dh1 = id_key.exchange(ec.ECDH(), peer_sp_key)
    dh2 = eph_key.exchange(ec.ECDH(), peer_id_key)
    dh3 = eph_key.exchange(ec.ECDH(), peer_sp_key)
    dh4 = b""

    if "otp_key" in header:
        peer_otp_key = serialization.load_der_public_key(base64.b64decode(header["otp_key"]))
        dh4 = eph_key.exchange(ec.ECDH(), peer_otp_key)

    shared_key = HKDF(SHA256(), 32, b"", b"x3dh").derive(dh1 + dh2 + dh3 + dh4)
    additional_data = HKDF(SHA256(), 32, b"", b"ad").derive(id_key.exchange(ec.ECDH(), peer_id_key))

    init_msg = {
        "alternate": header["alternate"],
        "eph_key": base64.b64encode(eph_key.public_key().public_bytes(**ser_args)).decode("ascii"),
        "id_key": base64.b64encode(id_key.public_key().public_bytes(**ser_args)).decode("ascii"),
    }

    if "otp_ind" in header:
        init_msg["otp_ind"] = header["otp_ind"]

    ratchet = DoubleRatchet.init_sender(
        additional_data, shared_key, peer_sp_key, init_msg
    )

    return ratchet

def init_receiver(header, id_key, sp_key, otp_keys):
    peer_id_key = serialization.load_der_public_key(base64.b64decode(header["id_key"]))
    peer_eph_key = serialization.load_der_public_key(base64.b64decode(header["eph_key"]))

    dh1 = sp_key.exchange(ec.ECDH(), peer_id_key)
    dh2 = id_key.exchange(ec.ECDH(), peer_eph_key)
    dh3 = sp_key.exchange(ec.ECDH(), peer_eph_key)
    dh4 = b""

    if "otp_ind" in header:
        otp_key = otp_keys[header["otp_ind"]]
        dh4 = otp_key.exchange(ec.ECDH(), peer_eph_key)

    shared_key = HKDF(SHA256(), 32, b"", b"x3dh").derive(dh1 + dh2 + dh3 + dh4)
    additional_data = HKDF(SHA256(), 32, b"", b"ad").derive(id_key.exchange(ec.ECDH(), peer_id_key))

    ratchet = DoubleRatchet.init_receiver(additional_data, shared_key, sp_key)
    
    return ratchet

if __name__ == "__main__":
    alternate = True

    a_id_key = ec.generate_private_key(ec.SECP256R1)
    a_sp_key = ec.generate_private_key(ec.SECP256R1)
    a_sp_key_sig = a_id_key.sign(a_sp_key.public_key().public_bytes(**ser_args), ec.ECDSA(SHA256()))
    a_otp_keys = [ec.generate_private_key(ec.SECP256R1) for _ in range(10)]

    header = {
        "alternate": alternate,
        "id_key": base64.b64encode(a_id_key.public_key().public_bytes(**ser_args)).decode("ascii"),
        "sp_key": base64.b64encode(a_sp_key.public_key().public_bytes(**ser_args)).decode("ascii"),
        "sp_key_sig": base64.b64encode(a_sp_key_sig).decode("ascii"),
        "otp_key": base64.b64encode(a_otp_keys[3].public_key().public_bytes(**ser_args)).decode("ascii"),
        "otp_ind": 3,
    }

    import os
    password = os.urandom(16)

    b_id_key = ec.generate_private_key(ec.SECP256R1)

    b = init_sender(b_id_key, header)

    header, ciphertext = b.encrypt(b"8")

    a = init_receiver(header, a_id_key, a_sp_key, a_otp_keys)

    print(a.decrypt(header, ciphertext))
    
    x1 = a.encrypt(b"stuff")
    print(b.decrypt(*x1))
    x2 = a.encrypt(b"stuff")
    x3 = a.encrypt(b"things")
    print(b.decrypt(*x3))
    b = b.from_serialized(b.serialize())
    print(b.decrypt(*x2))

    a = a.from_serialized(a.serialize())

    x1 = b.encrypt(b"stuff")
    print(a.decrypt(*x1))
    x2 = b.encrypt(b"stuff")
    x3 = b.encrypt(b"things")
    print(a.decrypt(*x3))
    print(a.decrypt(*x2))
