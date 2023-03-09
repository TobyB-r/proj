from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
from double_ratchet import DoubleRatchet

ser_args = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}

# the sender initializes shared key from public keys received from the server
# the user we are trying to talk to has the corresponding private keys
# for our private keys we use our identity key and an ephemeral key generated just for this exchange
def init_sender(id_key, header):
    eph_key = ec.generate_private_key(ec.SECP256R1)
    
    peer_sp_key = base64.b64decode(header["sp_key"])
    peer_id_key = serialization.load_der_public_key(base64.b64decode(header["id_key"]))
    peer_key_sig = base64.b64decode(header["sp_key_sig"])

    # verifying the signed key
    peer_id_key.verify(peer_key_sig, peer_sp_key, ec.ECDSA(SHA256()))

    peer_sp_key = serialization.load_der_public_key(peer_sp_key)

    dh1 = id_key.exchange(ec.ECDH(), peer_sp_key)
    dh2 = eph_key.exchange(ec.ECDH(), peer_id_key)
    dh3 = eph_key.exchange(ec.ECDH(), peer_sp_key)
    dh4 = b""

    # we may not have been sent an otp key if the server has sent all of them already
    if "otp_key" in header:
        peer_otp_key = serialization.load_der_public_key(base64.b64decode(header["otp_key"]))
        dh4 = eph_key.exchange(ec.ECDH(), peer_otp_key)

    # shared key initializes the root key for the double ratchet
    shared_key = HKDF(SHA256(), 32, b"", b"x3dh").derive(dh1 + dh2 + dh3 + dh4)
    # additional data is used to authenticate encryption and users can compare it to prevent mitm attacks
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

# the receiver uses our id key, signed key and otp keys
# the sender gives us the values for their id and ephemeral keys
def init_receiver(header, id_key, sp_key, otp_keys):
    peer_id_key = serialization.load_der_public_key(base64.b64decode(header["id_key"]))
    peer_eph_key = serialization.load_der_public_key(base64.b64decode(header["eph_key"]))

    dh1 = sp_key.exchange(ec.ECDH(), peer_id_key)
    dh2 = id_key.exchange(ec.ECDH(), peer_eph_key)
    dh3 = sp_key.exchange(ec.ECDH(), peer_eph_key)
    dh4 = b""

    # if the server ran out of otp_keys the other user may not have used any
    if "otp_ind" in header:
        otp_key = otp_keys[header["otp_ind"]]
        dh4 = otp_key.exchange(ec.ECDH(), peer_eph_key)
    
    # shared key initializes the root key for the double ratchet
    shared_key = HKDF(SHA256(), 32, b"", b"x3dh").derive(dh1 + dh2 + dh3 + dh4)
    # additional data is used to authenticate encryption and users can compare it to prevent mitm attacks
    additional_data = HKDF(SHA256(), 32, b"", b"ad").derive(id_key.exchange(ec.ECDH(), peer_id_key))

    ratchet = DoubleRatchet.init_receiver(additional_data, shared_key, sp_key)
    
    return ratchet
