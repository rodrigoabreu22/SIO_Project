from dotenv import load_dotenv
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7
import base64

load_dotenv()
def load_rep_privkey():
    priv_key = os.getenv("PRIVATE_KEY")
    if not priv_key:
        print("Private key not found")
        sys.exit(-1)
    return priv_key

def decrypt_data(data_encrypt, priv_key):
    private_key = serialization.load_pem_private_key(priv_key.encode(), password=None)

    key = private_key.decrypt(
        data_encrypt["key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    mac_key = private_key.decrypt(
        data_encrypt["mac_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data_encrypt["key"])
    h.verify(data_encrypt["mac"])

    cipher = Cipher(algorithms.AES(key), modes.CBC(data_encrypt["iv"]))
    decryptor = cipher.decryptor()
    data_decrypted = decryptor.update(data_encrypt["payload"]) + decryptor.finalize()
    rem_padder = PKCS7(128).unpadder()
    data = rem_padder.update(data_decrypted) + rem_padder.finalize()

    return data.decode()

def string_bytes(payload):
    dec_pay = {}
    for key, value in payload.items():
        if isinstance(value, str):
            try:
                dec_pay[key] = base64.b64decode(value)
            except:
                dec_pay[key] = value
        
        else:
            dec_pay[key] = value

    return dec_pay