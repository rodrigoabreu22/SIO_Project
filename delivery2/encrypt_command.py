from dotenv import load_dotenv
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7
import base64


load_dotenv()
def load_rep_pubkey():
    pub_key = os.getenv("PUBLIC_KEY")
    if not pub_key:
        print("Public key not found")
        sys.exit(-1)
    return pub_key

def encrypt_data(payload, pub_key):
    key = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = PKCS7(128).padder()
    data = padder.update(payload.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    payload_encrypted = encryptor.update(data) + encryptor.finalize()

    public_key = serialization.load_pem_public_key(pub_key.encode())

    key_encrypted = public_key.encrypt(
        key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    #calculate mac with hmac
    mac_key = os.urandom(32)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(key_encrypted)
    mac = h.finalize()

    mac_key_encrypted = public_key.encrypt(
        mac_key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    data_encrypted = {
        "payload": payload_encrypted,
        "key": key_encrypted,
        "iv": iv,
        "mac": mac,
        "mac_key": mac_key_encrypted
    }

    return data_encrypted

def bytes_to_string(payload):
    enc_pay = {}

    for key, value in payload.items():
        if isinstance(value, bytes):
            enc_pay[key] = base64.b64encode(value).decode("utf-8")
        else:
            enc_pay[key] = value
    
    return enc_pay