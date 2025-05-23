from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from ecdsa import SigningKey, VerifyingKey, SECP256k1, ECDH


def generate_ecdsa():
    priv_key = SigningKey.generate(curve=SECP256k1)
    verif_key = priv_key.get_verifying_key()
    return priv_key, verif_key


def generate_ecdh(priv_key):
    ecdh = ECDH(curve=SECP256k1)
    ecdh.load_private_key(priv_key)
    return ecdh


def derive_shared_key(ecdh, client_public_bytes, identity):
    ecdh.load_received_public_key_bytes(client_public_bytes)
    shared_secret = ecdh.generate_sharedsecret_bytes()
    return SHA256.new(shared_secret + identity.encode()).digest()[:8]  # DES key = 8 bytes


def hash_message(message):
    return SHA256.new(message).digest()


def signing(priv_key, msg):
    return priv_key.sign(msg)


def verify_signature(public_bytes, signature, msg):
    verif_key = VerifyingKey.from_string(public_bytes, curve=SECP256k1)
    return verif_key.verify(signature, msg)


def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    pad_len = 8 - len(data) % 8
    return cipher.encrypt(data + bytes([pad_len]) * pad_len)


def des_decrypt(data):
    key = None  # Placeholder: must be set per-session
    raise NotImplementedError("Key must be passed in per decryption")


def des_decrypt_with_key(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]
