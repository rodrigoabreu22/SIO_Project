from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from encrypt_command import load_rep_pubkey
import sys

def sign_data_coms(data, key: str):
    priv_key = serialization.load_pem_private_key(key.encode(), password=None)
    signature = priv_key.sign(json.dumps(data, sort_keys=True).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    return {"payload_sign": data, "signature": signature.hex()}

def verify_signature_coms(message, key: str):
    pub_key = serialization.load_pem_public_key(key.encode())
    response = message.get("payload_sign")
    signature = bytes.fromhex(message.get("signature"))

    try:
        pub_key.verify(
            signature,
            json.dumps(response, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature as e:
        return False
    
def verify_signature_coms_unpack(message, key: str):
    pub_key = serialization.load_pem_public_key(key.encode())
    response = message.get("payload_sign")
    signature = bytes.fromhex(message.get("signature"))

    try:
        pub_key.verify(
            signature,
            json.dumps(response, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return response
    except InvalidSignature as e:
        print(e)
        sys.exit(1)